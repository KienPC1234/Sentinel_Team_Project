import json
import re
import logging
import base64
import uuid
import io
from typing import List, Dict, Generator
from PIL import Image
from django.conf import settings
from django.core.files.base import ContentFile
from .ollama_client import stream_chat_ai, generate_response, filter_thinking
from .vector_db import vector_db
from api.ai_chat.models import ChatSession, ChatMessage, ChatMessageImage

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """Bạn là ShieldCall AI - chuyên gia an ninh mạng thông minh của ShieldCall VN.
Nhiệm vụ của bạn là bảo vệ người dùng khỏi lừa đảo, tấn công mạng và giúp họ sử dụng ứng dụng ShieldCall hiệu quả.

QUY TẮC QUAN TRỌNG:
1. Luôn phản hồi lịch sự, thân thiện bằng tiếng Việt.
2. Nếu người dùng hỏi về các chủ đề lừa đảo, hãy sử dụng thông tin trong [CONTEXT] để trả lời chính xác nhất.
3. Luôn TIN TƯỞNG TUYỆT ĐỐI vào kết quả từ các CÔNG CỤ (TOOLS). Các công cụ sẽ trả về dữ liệu văn bản để bạn phân tích và giải thích cho người dùng.
4. Khi nhận được [Nội dung từ ảnh] (OCR), hãy lưu ý rằng công nghệ OCR có thể gặp lỗi chữ (typos) hoặc nhầm ký tự. Đừng vội vàng kết luận đó là dấu hiệu lừa đảo chỉ vì lỗi chính tả trong ảnh. 
5. Đừng tự ý đưa ra kết luận nếu chưa có đủ thông tin, hãy hướng dẫn người dùng sử dụng các chức năng quét của ShieldCall.

HÔM NAY LÀ: {current_time}
"""

class AIAgent:
    def __init__(self, session_id=None, user=None):
        self.session_id = session_id
        self.user = user
        self.session = None
        if session_id:
            from django.core.exceptions import ValidationError
            try:
                # Use filter().first() to avoid DoesNotExist exceptions during initialization
                self.session = ChatSession.objects.filter(id=session_id).first()
                if not self.session:
                    logger.warning(f"Session {session_id} not found, creating new one for user {user}")
                    self.session = ChatSession.objects.create(user=user)
                    self.session_id = self.session.id
            except (ValidationError, ValueError) as e:
                logger.error(f"Invalid session ID {session_id}: {e}")
                self.session = ChatSession.objects.create(user=user)
                self.session_id = self.session.id
        elif user:
            self.session = ChatSession.objects.create(user=user)
            self.session_id = self.session.id

    def _get_history(self, limit=10) -> List[Dict]:
        if not self.session:
            return []
        messages = self.session.messages.all().order_by('-created_at')[:limit]
        history = []
        for msg in reversed(messages):
            history.append({"role": msg.role, "content": msg.message})
        return history

    def _get_rag_context(self, user_query: str) -> str:
        # We can't yield directly from a helper if it's not a generator
        # but we can log or just let chat_stream handle the status.
        results = vector_db.search(user_query, k=2)
        if not results:
            logger.info(f"RAG: No hits found for query: '{user_query[:50]}'")
            return "", []
        
        logger.info(f"RAG: Found {len(results)} hits for query: '{user_query[:50]}'")
        for i, res in enumerate(results):
            logger.info(f"   Hit {i+1}: {res.get('title')} (score: {res.get('score', 'N/A')})")
        
        context_str = "\n--- THÔNG TIN THAM KHẢO TỪ SHIELDCALL VN ---\n"
        for res in results:
            context_str += f"Nguồn: {res['title']} ({res['url']})\nNội dung: {res['text']}\n\n"
        return context_str, results

    def chat_stream(self, user_message: str, images_data: List[str] = None) -> Generator[str, None, None]:
        """
        Main entry point for streaming chat with RAG and History.
        """
        # 1. Save user message
        if self.session:
            user_msg = ChatMessage.objects.create(
                session=self.session,
                role='user',
                message=user_message
            )
            # Save images if provided
            if images_data:
                for img_b64 in images_data:
                    try:
                        if ',' in img_b64:
                            header, data = img_b64.split(',', 1)
                        else:
                            data = img_b64
                        
                        img_bytes = base64.b64decode(data)
                        
                        # Compress image using PIL
                        img = Image.open(io.BytesIO(img_bytes))
                        # Convert to RGB if necessary (e.g. for PNG with alpha)
                        if img.mode in ("RGBA", "P"):
                            img = img.convert("RGB")
                        
                        output = io.BytesIO()
                        img.save(output, format='JPEG', quality=80, optimize=True)
                        output.seek(0)
                        
                        img_name = f"chat_{uuid.uuid4().hex[:8]}.jpg"
                        ChatMessageImage.objects.create(
                            message=user_msg,
                            image=ContentFile(output.read(), name=img_name)
                        )
                    except Exception as e:
                        logger.error(f"Error saving chat image: {e}")

        # 2. Get Context & History
        yield "__STATUS__:searching_knowledge"
        history = self._get_history()
        rag_context, rag_results = self._get_rag_context(user_message)
        
        current_metadata = {}
        if rag_results:
            current_metadata['internal_knowledge'] = rag_results
            yield f"__METADATA__:{json.dumps(current_metadata)}"
        
        # 3. Construct Final Prompt
        from datetime import datetime
        now = datetime.now()
        time_str = now.strftime("%A, ngày %d/%m/%Y, %H:%M:%S")
        
        messages = [{"role": "system", "content": SYSTEM_PROMPT.format(current_time=time_str)}]
        if rag_context:
            messages.append({"role": "system", "content": f"SỬ DỤNG BỐI CẢNH SAU ĐỂ TRẢ LỜI:\n{rag_context}"})
        
        messages.extend(history)
        # Ensure the latest message is the user query (it might have been saved already if history was empty)
        if not history or history[-1]['content'] != user_message:
             messages.append({"role": "user", "content": user_message})

        full_response = ""
        try:
            # 3. Use the improved stream_chat_ai from ollama_client
            for chunk in stream_chat_ai(messages):
                # Capture search results for metadata persistence
                if chunk.startswith("__SEARCH_RESULTS__:") or chunk.startswith("__METADATA__:"):
                    try:
                        marker = "__SEARCH_RESULTS__:" if chunk.startswith("__SEARCH_RESULTS__:") else "__METADATA__:"
                        results = json.loads(chunk[len(marker) :])
                        if marker == "__METADATA__":
                            current_metadata.update(results)
                        else:
                            current_metadata['web_search'] = results
                        
                        # Forward as __METADATA__ for consistent frontend handling
                        if marker == "__SEARCH_RESULTS__":
                            yield f"__METADATA__:{json.dumps({'web_search': results})}"
                        else:
                            yield chunk
                        continue
                    except: pass

                # Handle Tool Markers for Frontend Widgets (Hiding raw metadata from UI)
                if chunk.startswith("__TOOL_CALLS__:"):
                    try:
                        tcs = json.loads(chunk[len("__TOOL_CALLS__:") :])
                        for tc in tcs:
                            fn = tc.get("function", {})
                            name = fn.get("name")
                            args = fn.get("arguments", {})
                            if isinstance(args, str):
                                args = json.loads(args)

                        # Internal marker yielding removed (user requested to hide [[SCAN_...]])
                        continue
                    except Exception as te:
                        logger.error(f"Tool Call Parse Error: {te}")
                        continue
                
                # Normal Yield (content, thinking, status, search_results)
                if chunk.startswith("__THINK__:"):
                    # Limit the total thinking yielded to user to save bandwidth/UI noise
                    think_content = chunk[10:]
                    if len(getattr(self, '_think_buffer', '')) < 1000:
                        self._think_buffer = getattr(self, '_think_buffer', '') + think_content
                        yield chunk
                    continue

                yield chunk
                if not chunk.startswith("__"):
                    full_response += chunk

            # 4. Save assistant response to history
            if self.session and full_response:
                # Clean internal markers before saving to DB
                clean_msg = full_response
                # Markers to remove from DB storage (but keep '[[SCAN_' as it's used for rendering history)
                internal_markers = ["__THINK__:", "__STATUS__:", "__SEARCH_RESULTS__:", "__TOOL_CALLS__:", "[[SCAN_"]
                for marker in internal_markers:
                    if marker in clean_msg:
                        if marker == "[[SCAN_":
                            # Special handling for legacy tags if they leaked
                            clean_msg = re.sub(r"\[\[SCAN_[^\]]*\]\]\n?", "", clean_msg)
                        else:
                            clean_msg = re.sub(rf"{re.escape(marker)}[^\n]*\n?", "", clean_msg)
                
                ChatMessage.objects.create(
                    session=self.session,
                    role='assistant',
                    message=clean_msg.strip(),
                    metadata=current_metadata if current_metadata else None
                )
                
                # 5. Auto-Title Generation (If still default)
                if self.session:
                    self.session.refresh_from_db()
                    logger.info(f"[DEBUG] Session {self.session.id} current title: '{self.session.title}'")
                    if self.session.title == "Cuộc trò chuyện mới" or not self.session.title:
                        logger.info(f"Generating title for session {self.session.id}...")
                        new_title = self.generate_title(user_message)
                        if new_title:
                            logger.info(f"Generated new title: '{new_title}' and saved to DB.")
                            yield f"__TITLE__:{new_title}"
                        else:
                            logger.warning("Title generation returned empty string")
                    else:
                        logger.info(f"Session {self.session.id} already has title, skipping generation.")
                    
        except Exception as e:
            logger.error(f"Agent Stream Error: {e}", exc_info=True)
            yield f"\n[Lỗi kết nối AI: {str(e)}]"

    def generate_title(self, first_message: str) -> str:
        """Generates a concise and engaging title for the chat session using a faster model."""
        from .ollama_client import SMALL_MODEL, generate_response
        
        # Clean up the input message for the prompt
        clean_input = first_message[:100].replace('\n', ' ').strip()
        prompt = (
            f"Dựa trên tin nhắn sau, hãy tạo một tiêu đề (2-6 từ) để tóm tắt nội dung.\n"
            f"Tin nhắn: '{clean_input}'\n"
            f"Yêu cầu: Chỉ trả về tiêu đề tiếng Việt, không giải thích, không ngoặc kép, không có tiền tố 'Tiêu đề:'."
        )
        
        try:
            # Use SMALL_MODEL for fast title generation
            title = generate_response(prompt, model=SMALL_MODEL, max_tokens=30)
            if title:
                # 1. Basic cleaning
                title = title.strip().replace('"', '').replace("'", "").replace("[", "").replace("]", "")
                if title.lower().startswith("tiêu đề:"):
                    title = title[8:].strip()
                
                # 2. Advanced deduplication for repeating loops (e.g. "ABCABCABC")
                for length in range(len(title) // 2, 2, -1):
                    for i in range(len(title) - length * 2 + 1):
                        slice1 = title[i : i + length]
                        slice2 = title[i + length : i + length * 2]
                        if slice1 == slice2 and slice1.strip():
                            title = title[: i + length]
                            break
                
                # 3. Strict word limit
                words = title.split()
                if len(words) > 6:
                    title = " ".join(words[:6])
                
                if not title:
                    return ""

                self.session.title = title
                self.session.save()
                return title
        except Exception as e:
            logger.error(f"Generate title error: {e}")
        
        # Fallback: Best effort title from first message
        words = first_message.split()
        fallback_title = " ".join(words[:4])
        if len(words) > 4:
            fallback_title += "..."
        if fallback_title:
            self.session.title = fallback_title
            self.session.save()
            return fallback_title
            
        return ""

def get_agent(session_id=None, user=None):
    return AIAgent(session_id, user)
