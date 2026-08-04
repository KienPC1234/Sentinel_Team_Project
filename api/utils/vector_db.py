import os
import faiss
import numpy as np
import pickle
import logging
import warnings
import transformers.utils.logging

# Suppress transformers/sentence-transformers warnings
transformers.utils.logging.set_verbosity_error()
logging.getLogger("transformers.modeling_utils").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", message=".*embeddings.position_ids.*")

from sentence_transformers import SentenceTransformer
from django.conf import settings
# from api.core.models import Article, LearnLesson

logger = logging.getLogger(__name__)

INDEX_PATH = os.path.join(settings.BASE_DIR, 'media', 'vector_index', 'scam_index.faiss')
METADATA_PATH = os.path.join(settings.BASE_DIR, 'media', 'vector_index', 'metadata.pkl')
MODEL_NAME = 'paraphrase-multilingual-MiniLM-L12-v2'

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

    def _load_model(self):
        if self._model is None:
            logger.info(f"Loading embedding model: {MODEL_NAME}")
            # Ensure we load in a way that doesn't trigger unnecessary warnings
            self._model = SentenceTransformer(MODEL_NAME, device='cpu')

    def load_index(self):
        if os.path.exists(INDEX_PATH) and os.path.exists(METADATA_PATH):
            try:
                self.index = faiss.read_index(INDEX_PATH)
                with open(METADATA_PATH, 'rb') as f:
                    self.metadata = pickle.load(f)
                logger.info(f"Loaded vector index with {len(self.metadata)} items")
            except Exception as e:
                logger.error(f"Error loading index: {e}")
                self.index = None
                self.metadata = []
        else:
            logger.warning("Index files not found. Need to rebuild.")

    def save_index(self):
        os.makedirs(os.path.dirname(INDEX_PATH), exist_ok=True)
        if self.index:
            faiss.write_index(self.index, INDEX_PATH)
            with open(METADATA_PATH, 'wb') as f:
                pickle.dump(self.metadata, f)
            logger.info("Saved vector index and metadata")

    def rebuild_index(self):
        """
        Fetches all published Articles, Lessons, Quizzes, and Scenarios,
        embeds them, and creates a new FAISS index.
        """
        if self._model is None:
            self._load_model()
        logger.info("Rebuilding vector index...")
        documents = []
        metadata = []

        from api.core.models import Article, LearnLesson, LearnQuiz, LearnScenario

        # Fetch Articles
        articles = Article.objects.filter(is_published=True)
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
        for q in quizzes:
            text = f"Câu hỏi: {q.question}\nGiải thích: {q.explanation}"
            documents.append(text)
            metadata.append({
                'id': q.id,
                'type': 'quiz',
                'title': f"Quiz: {q.question[:50]}",
                'url': f"/learn/{(q.article.slug if q.article else q.lesson.slug) if (q.article or q.lesson) else ''}/"
            })

        # Fetch Scenarios
        scenarios = LearnScenario.objects.filter(article__is_published=True)
        for s in scenarios:
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

        # Embed documents
        embeddings = self._model.encode(documents, convert_to_numpy=True)
        
        # Create FAISS index
        dimension = embeddings.shape[1]
        self.index = faiss.IndexFlatL2(dimension)
        self.index.add(embeddings.astype('float32'))
        self.metadata = metadata
        
        self.save_index()
        logger.info(f"Rebuilt index with {len(documents)} items.")

    def search(self, query, k=3):
        """
        Searches for top-k similar documents.
        Returns a list of matching metadata and text snippets.
        """
        if self._model is None:
            self._load_model()
        if self.index is None:
            self.load_index()
            if self.index is None:
                return []

        query_vector = self._model.encode([query], convert_to_numpy=True)
        distances, indices = self.index.search(query_vector.astype('float32'), k)
        
        results = []
        article_ids = []
        lesson_ids = []
        raw_results = []

        for i, idx in enumerate(indices[0]):
            if idx != -1 and idx < len(self.metadata):
                res = self.metadata[idx].copy()
                res['score'] = float(distances[0][i])
                raw_results.append(res)
                if res['type'] == 'article':
                    article_ids.append(res['id'])
                else:
                    lesson_ids.append(res['id'])

        # Batch fetch objects to reduce DB hits
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
        
        return results

# Shortcut for singleton access
vector_db = ScamVectorDB()
