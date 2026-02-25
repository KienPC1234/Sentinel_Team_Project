import os
import faiss
import numpy as np
import pickle
import logging
import warnings
import transformers.utils.logging
from sentence_transformers import SentenceTransformer
import torch
from django.conf import settings

# Suppress transformers/sentence-transformers warnings
transformers.utils.logging.set_verbosity_error()
logging.getLogger("transformers.modeling_utils").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", message=".*embeddings.position_ids.*")

# Set HF_TOKEN if available in settings to avoid hub warnings
HF_TOKEN = getattr(settings, 'HF_TOKEN', None)
if HF_TOKEN:
    os.environ['HF_TOKEN'] = HF_TOKEN

logger = logging.getLogger(__name__)

INDEX_PATH = os.path.join(settings.BASE_DIR, 'media', 'vector_index', 'scam_index.faiss')
METADATA_PATH = os.path.join(settings.BASE_DIR, 'media', 'vector_index', 'metadata.pkl')
MODEL_NAME = 'nomic-ai/nomic-embed-text-v1'
USE_GPU = getattr(settings, 'VECTOR_DB_USE_GPU', True)

class ScamVectorDB:
    _instance = None
    _model = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ScamVectorDB, cls).__new__(cls)
            cls._instance.index = None
            cls._instance.metadata = []
            cls._instance.load_index()
        return cls._instance

    def _load_model(self, force_cpu=False):
        if self._model is None:
            # For background tasks (like rebuild), sometimes CPU is safer to avoid CUDA fork issues
            use_cuda = USE_GPU and torch.cuda.is_available() and not force_cpu
            device = "cuda" if use_cuda else "cpu"
            
            # Check if we are in a forked process and CUDA was already initialized
            if device == "cuda" and torch.cuda.is_initialized():
                # If we're already initialized but in a fork, we MUST use CPU or it will crash
                pass

            logger.info(f"Loading embedding model: {MODEL_NAME} on {device}")
            try:
                self._model = SentenceTransformer(MODEL_NAME, device=device, trust_remote_code=True)
                logger.info(f"Model loaded successfully on {device}")
            except Exception as e:
                logger.error(f"Failed to load model on {device}: {e}")
                if device == "cuda":
                    logger.warning("Retrying on CPU...")
                    self._model = SentenceTransformer(MODEL_NAME, device="cpu", trust_remote_code=True)
                    logger.info("Model loaded successfully on CPU")
                else:
                    raise e

    def load_index(self):
        if os.path.exists(INDEX_PATH) and os.path.exists(METADATA_PATH):
            try:
                self.index = faiss.read_index(INDEX_PATH)
                with open(METADATA_PATH, 'rb') as f:
                    self.metadata = pickle.load(f)
                
                if self.index:
                    logger.info(f"Loaded vector index with {len(self.metadata)} items (dim={self.index.d})")
                
            except Exception as e:
                logger.error(f"Error loading index: {e}")
                self.index = None
                self.metadata = []
        else:
            logger.warning(f"Index files not found at {INDEX_PATH}. Need to rebuild.")

    def save_index(self):
        os.makedirs(os.path.dirname(INDEX_PATH), exist_ok=True)
        if self.index:
            faiss.write_index(self.index, INDEX_PATH)
            with open(METADATA_PATH, 'wb') as f:
                pickle.dump(self.metadata, f)
            logger.info(f"Saved vector index to {INDEX_PATH} and metadata to {METADATA_PATH}")

    def rebuild_index(self, force_cpu=False):
        """
        Fetches all published Articles, Lessons, Quizzes, and Scenarios,
        embeds them, and creates a new FAISS index.
        """
        if self._model is None:
            self._load_model(force_cpu=force_cpu)
        
        logger.info("Rebuilding vector index...")
        documents = []
        metadata = []

        from api.core.models import Article, LearnLesson, LearnQuiz, LearnScenario

        # Fetch Articles
        articles = Article.objects.filter(is_published=True)
        logger.info(f"Fetched {articles.count()} published articles.")
        for art in articles:
            text = f"Tiêu đề: {art.title}\nNội dung: {art.content}"
            documents.append(text)
            metadata.append({
                'id': art.id,
                'type': 'article',
                'title': art.title,
                'url': f"/learn/{art.slug}/"
            })

        # Fetch Lessons
        lessons = LearnLesson.objects.filter(is_published=True)
        logger.info(f"Fetched {lessons.count()} published lessons.")
        for les in lessons:
            text = f"Tiêu đề: {les.title}\nNội dung: {les.content}"
            documents.append(text)
            metadata.append({
                'id': les.id,
                'type': 'lesson',
                'title': les.title,
                'url': f"/learn/{les.slug}/"
            })

        # Fetch Quizzes
        quizzes = LearnQuiz.objects.filter(article__is_published=True) | LearnQuiz.objects.filter(lesson__is_published=True)
        logger.info(f"Fetched {quizzes.count()} relevant quizzes.")
        for q in quizzes:
            text = f"Câu hỏi: {q.question}\nGiải thích: {q.explanation}"
            documents.append(text)
            metadata.append({
                'id': q.id,
                'type': 'quiz',
                'title': f"Quiz: {q.question[:50]}",
                'url': f"/learn/{(q.article.slug if q.article else q.lesson.slug) if (q.article or q.lesson) else ''}/"
            })

        # Fetch Scenarios (include those without articles)
        scenarios = LearnScenario.objects.all()
        logger.info(f"Fetched {scenarios.count()} scenarios.")
        for s in scenarios:
            if s.article is None or s.article.is_published:
                text = f"Kịch bản: {s.title}\nMô tả: {s.description}"
                documents.append(text)
                metadata.append({
                    'id': s.id,
                    'type': 'scenario',
                    'title': s.title,
                    'url': f"/learn/{s.article.slug}/" if s.article else "/learn/"
                })

        if not documents:
            logger.warning("No documents found to index.")
            return

        logger.info(f"Embedding {len(documents)} total documents...")
        # Embed documents
        embeddings = self._model.encode(documents, convert_to_numpy=True, show_progress_bar=True)
        # Normalize for Cosine Similarity
        faiss.normalize_L2(embeddings)
        
        # Create FAISS index
        dimension = embeddings.shape[1]
        logger.info(f"Creating FAISS IndexFlatIP with dimension {dimension}...")
        self.index = faiss.IndexFlatIP(dimension)
        self.index.add(embeddings.astype('float32'))
        self.metadata = metadata
        
        self.save_index()
        logger.info(f"Rebuilt index with {len(documents)} items successfully.")

    def search(self, query, k=3):
        if self._model is None:
            self._load_model()
        if self.index is None:
            logger.warning("Search called but index is none.")
            return []

        if self.index.d != self._model.get_sentence_embedding_dimension():
            logger.error(f"Dimension mismatch: Index({self.index.d}) != Model({self._model.get_sentence_embedding_dimension()})")
            return []

        logger.info(f"RAG Search query: '{query}' (k={k})")
        query_vector = self._model.encode([query], convert_to_numpy=True)
        faiss.normalize_L2(query_vector)
        
        try:
            distances, indices = self.index.search(query_vector.astype('float32'), k)
        except Exception as e:
            logger.error(f"FAISS search crash: {e}")
            return []
        
        results = []
        article_ids = []
        lesson_ids = []
        raw_results = []
        THRESHOLD = 0.45

        for i, idx in enumerate(indices[0]):
            if idx != -1 and idx < len(self.metadata):
                dist = float(distances[0][i])
                logger.info(f"RAG Candidate [{i}]: '{self.metadata[idx].get('title')}' score={dist:.4f} type={self.metadata[idx].get('type')}")
                if dist < THRESHOLD:
                    logger.debug(f"Candidate rejected: score {dist:.4f} < {THRESHOLD}")
                    continue
                    
                res = self.metadata[idx].copy()
                res['score'] = dist
                raw_results.append(res)
                if res['type'] == 'article':
                    article_ids.append(res['id'])
                elif res['type'] == 'lesson':
                    lesson_ids.append(res['id'])

        from api.core.models import Article, LearnLesson, LearnQuiz, LearnScenario
        articles = {a.id: a for a in Article.objects.filter(id__in=article_ids)}
        lessons = {l.id: l for l in LearnLesson.objects.filter(id__in=lesson_ids)}
        
        quiz_ids = [res['id'] for res in raw_results if res['type'] == 'quiz']
        quizzes = {q.id: q for q in LearnQuiz.objects.filter(id__in=quiz_ids)}
        
        scenario_ids = [res['id'] for res in raw_results if res['type'] == 'scenario']
        scenarios = {s.id: s for s in LearnScenario.objects.filter(id__in=scenario_ids)}

        for res in raw_results:
            obj = None
            if res['type'] == 'article': obj = articles.get(res['id'])
            elif res['type'] == 'lesson': obj = lessons.get(res['id'])
            elif res['type'] == 'quiz': obj = quizzes.get(res['id'])
            elif res['type'] == 'scenario': obj = scenarios.get(res['id'])
            
            if obj:
                if res['type'] == 'quiz':
                    res['text'] = f"Câu hỏi: {obj.question}\nGiải thích: {obj.explanation}"
                elif res['type'] == 'scenario':
                    res['text'] = f"Kịch bản: {obj.title}\nMô tả: {obj.description}"
                else:
                    res['text'] = obj.content[:1000]
                results.append(res)
        
        logger.info(f"RAG Results: found {len(results)} matches above threshold {THRESHOLD}")
        return results

# Shortcut for singleton access
vector_db = ScamVectorDB()
