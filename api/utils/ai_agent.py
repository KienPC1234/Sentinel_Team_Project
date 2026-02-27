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

QUY TẮC:
1. Luôn phản hồi lịch sự, thân thiện bằng tiếng Việt.
2. Nếu người dùng hỏi về các chủ đề lừa đảo, hãy sử dụng các thông tin được cung cấp trong [CONTEXT] để trả lời chính xác nhất.
3. Khi bạn cần quét số điện thoại, tên miền/URL hoặc tài khoản ngân hàng, hãy SỬ DỤNG CÁC CÔNG CỤ (TOOLS) được cung cấp sẵn.
4. Đừng tự ý đưa ra kết luận nếu chưa có đủ thông tin, hãy hướng dẫn người dùng sử dụng các chức năng của ShieldCall.

[CONTEXT] Sẽ được hệ thống tự động chèn nếu có thông tin liên quan từ cơ sở dữ liệu bài học và tin tức của ShieldCall VN.
Nếu không có [CONTEXT], hãy trả lời dựa trên kiến thức bảo mật chuyên sâu của bạn.
"""

class AIAgent:
    def __init__(self, session_id=None, user=None):
        self.session_id = session_id
        self.user = user
        self.session = None
        if session_id:
            from django.core.exceptions import ValidationError
            try:
                self.session = ChatSession.objects.get(id=session_id)
            except (ChatSession.DoesNotExist, ValidationError, ValueError):
                self.session = ChatSession.objects.create(user=user)
                self.session_id = self.session.id
        elif user:
            # Create a new session if none provided but user is authenticated
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
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
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

                # Handle Tool Markers for Frontend Widgets
                if chunk.startswith("__TOOL_CALLS__:"):
                    try:
                        tcs = json.loads(chunk[len("__TOOL_CALLS__:") :])
                        for tc in tcs:
                            fn = tc.get("function", {})
                            name = fn.get("name")
                            args = fn.get("arguments", {})
                            if isinstance(args, str):
                                args = json.loads(args)

                            tool_marker = ""
                            if name == "scan_phone":
                                tool_marker = f"\n[[SCAN_PHONE:{args.get('phone')}]]\n"
                            elif name == "scan_url":
                                tool_marker = f"\n[[SCAN_DOMAIN:{args.get('url')}]]\n"
                            elif name == "scan_bank_account":
                                tool_marker = f"\n[[SCAN_ACCOUNT:{args.get('account_number')}]]\n"

                            if tool_marker:
                                yield tool_marker
                                full_response += tool_marker
                    except Exception as te:
                        logger.error(f"Tool Call Parse Error: {te}")
                
                # Normal Yield (content, thinking, status, search_results)
                yield chunk
                if not chunk.startswith("__"):
                    full_response += chunk

            # 4. Save assistant response to history
            if self.session and full_response:
                # Clean internal markers before saving to DB
                clean_msg = full_response
                # Markers to remove from DB storage (but keep '[[SCAN_' as it's used for rendering history)
                internal_markers = ["__THINK__:", "__STATUS__:", "__SEARCH_RESULTS__:", "__TOOL_CALLS__:"]
                for marker in internal_markers:
                    if marker in clean_msg:
                        # Remove marker and everything until the next newline or end of line
                        clean_msg = re.sub(rf"{re.escape(marker)}[^\n]*\n?", "", clean_msg)
                
                ChatMessage.objects.create(
                    session=self.session,
                    role='assistant',
                    message=clean_msg.strip(),
                    metadata=current_metadata if current_metadata else None
                )
                
                # 5. Auto-Title Generation (If first message)
                if self.session.messages.count() <= 2:
                    new_title = self.generate_title(user_message)
                    if new_title:
                        yield f"__TITLE__:{new_title}"
                    
        except Exception as e:
            logger.error(f"Agent Stream Error: {e}")
            yield f"\n[Lỗi kết nối AI: {str(e)}]"

    def generate_title(self, first_message: str) -> str:
        """Generates a concise title for the chat session."""
        prompt = f"Tạo một tiêu đề ngắn gọn (tối đa 6 từ) bằng tiếng Việt cho cuộc trò chuyện bắt đầu bằng: '{first_message}'. Chỉ trả về tiêu đề, không để trong ngoặc kép."
        try:
            title = generate_response(prompt)
            if title:
                title = title.strip().replace('"', '')
                self.session.title = title
                self.session.save()
                return title
        except:
            pass
        return ""

def get_agent(session_id=None, user=None):
    return AIAgent(session_id, user)
