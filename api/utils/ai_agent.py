import json
import logging
from typing import List, Dict, Generator
from django.conf import settings
from .ollama_client import stream_chat, generate_response, filter_thinking
from .vector_db import vector_db
from api.ai_chat.models import ChatSession, ChatMessage

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
            try:
                self.session = ChatSession.objects.get(id=session_id)
            except ChatSession.DoesNotExist:
                self.session = ChatSession.objects.create(id=session_id, user=user)
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
            return ""
        
        context_str = "\n--- THÔNG TIN THAM KHẢO TỪ SHIELDCALL VN ---\n"
        for res in results:
            context_str += f"Nguồn: {res['title']} ({res['url']})\nNội dung: {res['text']}\n\n"
        return context_str

    def chat_stream(self, user_message: str) -> Generator[str, None, None]:
        """
        Main entry point for streaming chat with RAG and History.
        """
        # 1. Save user message
        if self.session:
            ChatMessage.objects.create(
                session=self.session,
                role='user',
                message=user_message
            )

        # 2. Get Context & History
        yield "__STATUS__:searching_knowledge"
        history = self._get_history()
        rag_context = self._get_rag_context(user_message)
        
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
            for chunk in stream_chat(messages, use_tools=True):
                if chunk.startswith("__TOOL_CALLS__:"):
                    try:
                        tool_calls = json.loads(chunk[len("__TOOL_CALLS__:") :])
                        for tc in tool_calls:
                            fn = tc.get("function", {})
                            name = fn.get("name")
                            args = fn.get("arguments", {})
                            if isinstance(args, str):
                                args = json.loads(args)

                            tool_msg = ""
                            if name == "scan_phone":
                                val = args.get("phone")
                                tool_msg = f"\nTôi sẽ quét số điện thoại **{val}** ngay cho bạn: [[SCAN_PHONE:{val}]]\n"
                            elif name == "scan_url":
                                val = args.get("url")
                                tool_msg = f"\nTôi đang kiểm tra địa chỉ **{val}**: [[SCAN_DOMAIN:{val}]]\n"
                            elif name == "scan_bank_account":
                                val = args.get("account_number")
                                tool_msg = f"\nTôi sẽ quét số tài khoản **{val}** trên hệ thống: [[SCAN_ACCOUNT:{val}]]\n"

                            if tool_msg:
                                yield tool_msg
                                full_response += tool_msg
                    except Exception as te:
                        logger.error(f"Tool Call Parse Error: {te}")
                    continue

                full_response += chunk
                yield chunk
            
            # 4. Save Assistant response
            if self.session:
                ChatMessage.objects.create(
                    session=self.session,
                    role='assistant',
                    message=full_response
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
