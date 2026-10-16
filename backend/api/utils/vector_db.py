"""
RAG vector store (FAISS) — tối ưu cho độ trễ thấp & rebuild nhanh.

Tối ưu chính:
- **Query cache (LRU)**: lặp lại cùng câu hỏi → trả kết quả tức thì (không embed lại).
- **Embedding tăng dần**: cache vector theo hash nội dung → rebuild chỉ embed tài liệu mới/đổi.
- **Thread-safe**: khóa quanh load/save/rebuild; tự nạp lại khi file chỉ mục đổi (mtime).
- **Dedup kết quả** theo (type, id).
- **Backup/Khôi phục S3**: lưu chỉ mục lên object storage sau rebuild; tự khôi phục nếu thiếu file cục bộ.
"""
import hashlib
import logging
import os
import pickle
import threading
import warnings
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

import faiss
import numpy as np
from django.conf import settings

# Set HF_TOKEN if available in settings to avoid hub warnings
HF_TOKEN = getattr(settings, 'HF_TOKEN', None)
if HF_TOKEN:
    os.environ['HF_TOKEN'] = HF_TOKEN

logger = logging.getLogger(__name__)

_VECTOR_DIR = os.path.join(settings.BASE_DIR, 'vector_store')
INDEX_PATH = os.path.join(_VECTOR_DIR, 'scam_index.faiss')
METADATA_PATH = os.path.join(_VECTOR_DIR, 'metadata.pkl')
EMB_CACHE_PATH = os.path.join(_VECTOR_DIR, 'embedding_cache.pkl')
MODEL_NAME = 'nomic-ai/nomic-embed-text-v1'
USE_GPU = getattr(settings, 'VECTOR_DB_USE_GPU', True)
SCORE_THRESHOLD = float(getattr(settings, 'VECTOR_DB_SCORE_THRESHOLD', 0.45))
QUERY_CACHE_SIZE = int(getattr(settings, 'VECTOR_DB_QUERY_CACHE', 256))
EMBED_BATCH_SIZE = int(getattr(settings, 'VECTOR_DB_EMBED_BATCH', 32))


def _hash(text: str) -> str:
    return hashlib.sha1(text.encode('utf-8', errors='ignore')).hexdigest()


class ScamVectorDB:
    _instance = None
    _model = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ScamVectorDB, cls).__new__(cls)
            inst = cls._instance
            inst.index = None
            inst.metadata: List[Dict[str, Any]] = []
            inst._lock = threading.RLock()
            inst._index_mtime = 0.0
            inst._query_cache: "OrderedDict[str, List[Dict[str, Any]]]" = OrderedDict()
            inst.load_index()
        return cls._instance

    # ---------------------------------------------------------------- model
    def _dim(self) -> int:
        m = self._model
        try:
            return int(m.get_embedding_dimension())
        except Exception:
            return int(m.get_sentence_embedding_dimension())

    def _load_model(self, force_cpu: bool = False):
        if self._model is not None:
            return
        with self._lock:
            if self._model is not None:
                return
            import torch
            import transformers.utils.logging
            from sentence_transformers import SentenceTransformer

            try:
                faiss.omp_set_num_threads(min(8, os.cpu_count() or 4))
            except Exception:
                pass

            transformers.utils.logging.set_verbosity_error()
            logging.getLogger("transformers.modeling_utils").setLevel(logging.ERROR)
            warnings.filterwarnings("ignore", message=".*embeddings.position_ids.*")

            use_cuda = USE_GPU and torch.cuda.is_available() and not force_cpu
            device = "cuda" if use_cuda else "cpu"
            logger.info(f"Loading embedding model: {MODEL_NAME} on {device}")
            try:
                self._model = SentenceTransformer(MODEL_NAME, device=device, trust_remote_code=True)
            except Exception as e:
                logger.error(f"Failed to load model on {device}: {e}")
                if device == "cuda":
                    logger.warning("Retrying on CPU...")
                    self._model = SentenceTransformer(MODEL_NAME, device="cpu", trust_remote_code=True)
                else:
                    raise

    # ---------------------------------------------------------------- index
    def _current_index_mtime(self) -> float:
        try:
            return os.path.getmtime(INDEX_PATH)
        except OSError:
            return 0.0

    def load_index(self):
        with self._lock:
            if not (os.path.exists(INDEX_PATH) and os.path.exists(METADATA_PATH)):
                # Thử khôi phục từ object storage (S3) nếu có
                try:
                    from api.utils.s3_sync import restore_vector_store
                    if restore_vector_store():
                        logger.info("[VectorDB] Đã khôi phục chỉ mục từ S3.")
                except Exception as exc:
                    logger.warning(f"[VectorDB] restore from S3 skipped: {exc}")
            if not (os.path.exists(INDEX_PATH) and os.path.exists(METADATA_PATH)):
                logger.warning(f"Index files not found at {INDEX_PATH}. Need to rebuild.")
                return
            try:
                self.index = faiss.read_index(INDEX_PATH)
                with open(METADATA_PATH, 'rb') as f:
                    self.metadata = pickle.load(f)
                self._index_mtime = self._current_index_mtime()
                self._query_cache.clear()
                logger.info(f"Loaded vector index with {len(self.metadata)} items (dim={self.index.d})")
            except Exception as e:
                logger.error(f"Error loading index: {e}")
                self.index = None
                self.metadata = []

    def _maybe_reload(self):
        """Nạp lại nếu file chỉ mục đã đổi (ví dụ worker khác vừa rebuild)."""
        if self.index is not None and self._current_index_mtime() != self._index_mtime:
            logger.info("[VectorDB] Index file changed — reloading.")
            self.load_index()

    def save_index(self):
        with self._lock:
            os.makedirs(os.path.dirname(INDEX_PATH), exist_ok=True)
            if self.index is not None:
                faiss.write_index(self.index, INDEX_PATH)
                with open(METADATA_PATH, 'wb') as f:
                    pickle.dump(self.metadata, f)
                self._index_mtime = self._current_index_mtime()
                self._query_cache.clear()
                logger.info(f"Saved vector index to {INDEX_PATH} ({len(self.metadata)} items)")
                # Backup lên S3 (best-effort) để an toàn
                try:
                    from api.utils.s3_sync import backup_vector_store
                    stats = backup_vector_store()
                    logger.info(f"[VectorDB] Backup S3: {stats}")
                except Exception as exc:
                    logger.warning(f"[VectorDB] S3 backup skipped: {exc}")

    # ------------------------------------------------------ embedding cache
    def _load_emb_cache(self) -> Dict[str, List[float]]:
        try:
            with open(EMB_CACHE_PATH, 'rb') as f:
                data = pickle.load(f)
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
        return {}

    def _save_emb_cache(self, cache: Dict[str, List[float]]):
        try:
            os.makedirs(os.path.dirname(EMB_CACHE_PATH), exist_ok=True)
            with open(EMB_CACHE_PATH, 'wb') as f:
                pickle.dump(cache, f)
        except Exception as exc:
            logger.warning(f"[VectorDB] save embedding cache failed: {exc}")

    # --------------------------------------------------------- collect docs
    def _collect_documents(self) -> Tuple[List[str], List[Dict[str, Any]]]:
        import re
        from bs4 import BeautifulSoup
        from api.core.models import Article, LearnLesson, LearnQuiz, LearnScenario

        def _clean_text(raw: str) -> str:
            if not raw:
                return ''
            try:
                soup = BeautifulSoup(raw, 'html.parser')
                for s in soup(['script', 'style']):
                    s.decompose()
                text = soup.get_text(separator=' ', strip=True)
                return re.sub(r'\s+', ' ', text).strip()
            except Exception:
                return re.sub(r'<[^>]+>', ' ', raw).strip()

        documents: List[str] = []
        metadata: List[Dict[str, Any]] = []

        for art in Article.objects.filter(is_published=True):
            clean_body = _clean_text(art.content or '')
            clean_summary = (art.summary or '').strip()
            summary_part = f"\nTóm tắt: {clean_summary}" if clean_summary else ""
            documents.append(f"Tiêu đề: {art.title}{summary_part}\nNội dung: {clean_body[:3000]}")
            metadata.append({'id': art.id, 'type': 'article', 'title': art.title, 'url': f"/learn/{art.slug}/"})

        for les in LearnLesson.objects.filter(is_published=True):
            clean_body = _clean_text(les.content or '')
            clean_summary = (les.summary or '').strip()
            summary_part = f"\nTóm tắt: {clean_summary}" if clean_summary else ""
            documents.append(f"Tiêu đề: {les.title}{summary_part}\nNội dung: {clean_body[:3000]}")
            metadata.append({'id': les.id, 'type': 'lesson', 'title': les.title, 'url': f"/learn/lesson/{les.slug}/"})

        for q in (LearnQuiz.objects.filter(article__is_published=True) | LearnQuiz.objects.filter(lesson__is_published=True)).distinct():
            opts_parts = []
            if isinstance(q.options, list) and q.options:
                for opt in q.options:
                    if isinstance(opt, dict):
                        opts_parts.append(f"{opt.get('id', '')}. {opt.get('text', '')}".strip())
                    elif isinstance(opt, str):
                        opts_parts.append(opt)
            opts_text = ("\nLựa chọn: " + "; ".join(opts_parts)) if opts_parts else ""
            documents.append(f"Câu hỏi trắc nghiệm: {q.question}{opts_text}\nGiải thích: {q.explanation}")
            quiz_url = "/learn/"
            if q.lesson:
                quiz_url = f"/learn/lesson/{q.lesson.slug}/"
            elif q.article:
                quiz_url = f"/learn/{q.article.slug}/"
            metadata.append({'id': q.id, 'type': 'quiz', 'title': f"Quiz: {q.question[:50]}", 'url': quiz_url})

        for s in LearnScenario.objects.all():
            if s.article and not s.article.is_published:
                continue
            if s.lesson and not s.lesson.is_published:
                continue

            content = s.content or {}
            steps = content.get('steps') if isinstance(content, dict) else (content if isinstance(content, list) else [])
            steps_lines = []
            if steps:
                for st in steps:
                    if isinstance(st, dict):
                        actor = st.get('actor') or st.get('speaker') or 'Nhân vật'
                        txt = st.get('text') or ''
                        analysis = st.get('analysis') or st.get('note') or ''
                        line = f"{actor}: {txt}"
                        if analysis:
                            line += f" -> Phân tích: {analysis}"
                        steps_lines.append(line)
                    elif isinstance(st, str):
                        steps_lines.append(st)

            steps_text = ("\nDiễn biến chi tiết:\n" + "\n".join(steps_lines)) if steps_lines else ""
            documents.append(f"Kịch bản tình huống lừa đảo: {s.title}\nMô tả: {s.description}{steps_text}")

            scenario_url = "/learn/"
            if s.lesson:
                scenario_url = f"/learn/lesson/{s.lesson.slug}/"
            elif s.article:
                scenario_url = f"/learn/{s.article.slug}/"

            metadata.append({'id': s.id, 'type': 'scenario', 'title': s.title, 'url': scenario_url})

        return documents, metadata

    # ---------------------------------------------------------------- rebuild
    def rebuild_index(self, force_cpu: bool = False):
        self._load_model(force_cpu=force_cpu)
        documents, metadata = self._collect_documents()
        logger.info(f"Rebuilding vector index ({len(documents)} documents)...")

        if not documents:
            dim = self._dim()
            with self._lock:
                self.index = faiss.IndexFlatIP(dim)
                self.metadata = []
            self.save_index()
            return

        cache = self._load_emb_cache()
        hashes = [_hash(d) for d in documents]
        missing = [(i, documents[i]) for i, h in enumerate(hashes) if h not in cache]

        if missing:
            logger.info(f"Embedding {len(missing)}/{len(documents)} tài liệu mới/đổi (cache hit {len(documents)-len(missing)})...")
            idxs = [i for i, _ in missing]
            texts = [t for _, t in missing]
            vecs = self._model.encode(
                texts, convert_to_numpy=True, normalize_embeddings=True,
                batch_size=EMBED_BATCH_SIZE, show_progress_bar=False,
            )
            vecs = np.asarray(vecs, dtype='float32')
            for row, gi in enumerate(idxs):
                cache[hashes[gi]] = vecs[row].tolist()
            self._save_emb_cache(cache)

        dim = len(next(iter(cache.values())))
        embeddings = np.zeros((len(documents), dim), dtype='float32')
        for i, h in enumerate(hashes):
            embeddings[i] = cache[h]
        # cache đã normalize; chuẩn hoá lại cho chắc (rẻ)
        faiss.normalize_L2(embeddings)

        new_index = faiss.IndexFlatIP(dim)
        new_index.add(embeddings)
        with self._lock:
            self.index = new_index
            self.metadata = metadata
        self.save_index()
        logger.info(f"Rebuilt index with {len(documents)} items (dim={dim}).")

    # ---------------------------------------------------------------- search
    def search(self, query: str, k: int = 3) -> List[Dict[str, Any]]:
        self._load_model()
        self._maybe_reload()
        if self.index is None or getattr(self.index, 'ntotal', 0) == 0:
            return []

        if self.index.d != self._dim():
            logger.error(f"Dimension mismatch: Index({self.index.d}) != Model({self._dim()})")
            return []

        cache_key = f"{query.strip().lower()}::k={k}::th={SCORE_THRESHOLD}"
        cached = self._query_cache.get(cache_key)
        if cached is not None:
            self._query_cache.move_to_end(cache_key)
            return list(cached)

        query_vector = self._model.encode([query], convert_to_numpy=True, normalize_embeddings=True)
        try:
            distances, indices = self.index.search(np.asarray(query_vector, dtype='float32'), k)
        except Exception as e:
            logger.error(f"FAISS search crash: {e}")
            return []

        raw_results: List[Dict[str, Any]] = []
        seen = set()
        for i, idx in enumerate(indices[0]):
            if idx == -1 or idx >= len(self.metadata):
                continue
            dist = float(distances[0][i])
            if dist < SCORE_THRESHOLD:
                continue
            meta = self.metadata[idx]
            dedup_key = (meta.get('type'), meta.get('id'))
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            res = meta.copy()
            res['score'] = dist
            raw_results.append(res)

        results = self._attach_text(raw_results)

        # cập nhật LRU cache
        self._query_cache[cache_key] = list(results)
        self._query_cache.move_to_end(cache_key)
        while len(self._query_cache) > QUERY_CACHE_SIZE:
            self._query_cache.popitem(last=False)
        return results

    def _attach_text(self, raw_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        from api.core.models import Article, LearnLesson, LearnQuiz, LearnScenario

        ids_by_type: Dict[str, List[int]] = {}
        for res in raw_results:
            ids_by_type.setdefault(res['type'], []).append(res['id'])

        lookups: Dict[str, Dict[int, Any]] = {
            'article': {a.id: a for a in Article.objects.filter(id__in=ids_by_type.get('article', []))},
            'lesson': {l.id: l for l in LearnLesson.objects.filter(id__in=ids_by_type.get('lesson', []))},
            'quiz': {q.id: q for q in LearnQuiz.objects.filter(id__in=ids_by_type.get('quiz', []))},
            'scenario': {s.id: s for s in LearnScenario.objects.filter(id__in=ids_by_type.get('scenario', []))},
        }
        import re
        from bs4 import BeautifulSoup

        def _clean(raw: str) -> str:
            if not raw:
                return ''
            try:
                soup = BeautifulSoup(raw, 'html.parser')
                for s in soup(['script', 'style']):
                    s.decompose()
                text = soup.get_text(separator=' ', strip=True)
                return re.sub(r'\s+', ' ', text).strip()
            except Exception:
                return re.sub(r'<[^>]+>', ' ', raw).strip()

        results = []
        for res in raw_results:
            obj = lookups.get(res['type'], {}).get(res['id'])
            if not obj:
                continue
            if res['type'] == 'quiz':
                res['text'] = f"Câu hỏi: {obj.question}\nGiải thích: {obj.explanation}"
            elif res['type'] == 'scenario':
                content = obj.content or {}
                steps = content.get('steps') if isinstance(content, dict) else (content if isinstance(content, list) else [])
                steps_lines = []
                for st in steps:
                    if isinstance(st, dict):
                        actor = st.get('actor') or st.get('speaker') or 'Nhân vật'
                        txt = st.get('text') or ''
                        analysis = st.get('analysis') or st.get('note') or ''
                        line = f"- {actor}: {txt}"
                        if analysis:
                            line += f" [Phân tích bảo mật: {analysis}]"
                        steps_lines.append(line)
                    elif isinstance(st, str):
                        steps_lines.append(f"- {st}")
                steps_str = ("\nDiễn biến kịch bản:\n" + "\n".join(steps_lines)) if steps_lines else ""
                res['text'] = f"Kịch bản: {obj.title}\nMô tả: {obj.description}{steps_str}"
            else:
                body = _clean(obj.content or '')
                summary = (getattr(obj, 'summary', '') or '').strip()
                res['text'] = f"{summary}\n\n{body}"[:2000] if summary else body[:2000]
            results.append(res)
        return results

    # ---------------------------------------------------------------- helpers
    def invalidate_cache(self):
        self._query_cache.clear()

    def stats(self) -> Dict[str, Any]:
        return {
            'items': len(self.metadata),
            'dim': getattr(self.index, 'd', None),
            'cached_queries': len(self._query_cache),
            'index_mtime': self._index_mtime,
            'threshold': SCORE_THRESHOLD,
            'model': MODEL_NAME,
        }


# Shortcut for singleton access
vector_db = ScamVectorDB()


def preload_vector_db_async():
    """Warm up embedding model + index trong thread nền để giảm cold-start."""
    def _warmup():
        try:
            logger.info("[VectorDB] Starting background embedding model warm-up...")
            vector_db._load_model()
            vector_db._maybe_reload()
            logger.info("[VectorDB] Background warm-up finished successfully.")
        except Exception as e:
            logger.warning(f"[VectorDB] Background warm-up notice: {e}")

    threading.Thread(target=_warmup, daemon=True, name="VectorDB-Warmup").start()
