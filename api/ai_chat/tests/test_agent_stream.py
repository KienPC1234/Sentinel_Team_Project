import json
from unittest.mock import patch, MagicMock
from django.test import TestCase, AsyncClient
from django.contrib.auth import get_user_model
from django.urls import reverse

from api.ai_chat.models import ChatSession, ChatMessage
from api.utils.ollama_client import stream_chat_ai

User = get_user_model()


class MockMsg:
    def __init__(self, content="", thinking="", tool_calls=None):
        self.content = content
        self.thinking = thinking
        self.tool_calls = tool_calls or []


class MockChunk:
    def __init__(self, content="", thinking="", tool_calls=None):
        self.message = MockMsg(content, thinking, tool_calls)


def parse_sse_events(sse_text: str):
    """Helper to parse SSE events and decode json data."""
    events = []
    for line in sse_text.split('\n'):
        line = line.strip()
        if line.startswith('data:'):
            raw = line[5:].strip()
            if raw:
                try:
                    events.append(json.loads(raw))
                except Exception:
                    events.append({'raw': raw})
    return events


class StreamChatAILoopTest(TestCase):
    """
    Tests the multi-turn tool execution loop in stream_chat_ai.
    """

    @patch('api.utils.ollama_client._chat_stream_with_retry')
    def test_stream_direct_content_no_tools(self, mock_stream):
        """Verify normal stream yields content directly when no tool calls occur."""
        chunk1 = MockChunk(content="Chào bạn, ")
        chunk2 = MockChunk(content="tôi có thể giúp gì?")
        mock_stream.return_value = [chunk1, chunk2]

        messages = [{'role': 'user', 'content': 'Xin chào'}]
        generator = stream_chat_ai(messages)
        chunks = list(generator)

        self.assertIn("Chào bạn, ", chunks)
        self.assertIn("tôi có thể giúp gì?", chunks)
        self.assertFalse(any(c.startswith("__TOOL_CALLS__:") for c in chunks))

    @patch('api.utils.ollama_client._chat_stream_with_retry')
    def test_stream_thinking_phases(self, mock_stream):
        """Verify thinking chunks yield status transition and think markers."""
        chunk_think = MockChunk(thinking="Đang phân tích số điện thoại...")
        chunk_answer = MockChunk(content="Số này an toàn.")
        mock_stream.return_value = [chunk_think, chunk_answer]

        messages = [{'role': 'user', 'content': 'Check số này'}]
        chunks = list(stream_chat_ai(messages))

        self.assertIn("__STATUS__:thinking", chunks)
        self.assertIn("__THINK__:Đang phân tích số điện thoại...", chunks)
        self.assertIn("__STATUS__:answering", chunks)
        self.assertIn("Số này an toàn.", chunks)

    @patch('api.utils.ollama_client._chat_stream_with_retry')
    def test_stream_multi_turn_tool_dispatch(self, mock_stream):
        """Verify multi-turn tool dispatch executes tool and appends tool result to messages."""
        t1_chunk = MockChunk(tool_calls=[{
            'function': {
                'name': 'scan_phone',
                'arguments': {'phone_number': '0988776655'}
            }
        }])
        t2_chunk = MockChunk(content="Số điện thoại 0988776655 đã được xác minh.")
        mock_stream.side_effect = [[t1_chunk], [t2_chunk]]

        messages = [{'role': 'user', 'content': 'Tra cứu 0988776655'}]
        custom_tool_called = {}

        def mock_scan_phone(phone_number: str):
            custom_tool_called['phone'] = phone_number
            return {'is_scam': False, 'risk_level': 'SAFE'}

        chunks = list(stream_chat_ai(messages, tool_dispatch={'scan_phone': mock_scan_phone}))

        # Assert tool was dispatched with correct args
        self.assertEqual(custom_tool_called.get('phone'), '0988776655')

        # Assert markers yielded to frontend
        tool_call_marker = next(c for c in chunks if c.startswith("__TOOL_CALLS__:"))
        self.assertIn('scan_phone', tool_call_marker)

        tool_result_marker = next(c for c in chunks if c.startswith("__TOOL_RESULT__:"))
        self.assertIn('"status": "done"', tool_result_marker)
        self.assertIn('SAFE', tool_result_marker)

        # Assert messages updated for multi-turn
        assistant_turn = next(m for m in messages if m.get('role') == 'assistant')
        self.assertTrue(assistant_turn.get('tool_calls'))

        tool_turn = next(m for m in messages if m.get('role') == 'tool')
        self.assertEqual(tool_turn.get('tool_name'), 'scan_phone')

        # Final answer yielded
        self.assertIn("Số điện thoại 0988776655 đã được xác minh.", chunks)

    @patch('api.utils.ollama_client._chat_stream_with_retry')
    def test_stream_unknown_tool_graceful_handling(self, mock_stream):
        """Verify requesting an invalid tool does not crash and passes error to messages."""
        t1_chunk = MockChunk(tool_calls=[{
            'function': {
                'name': 'nonexistent_tool_xyz',
                'arguments': {'arg': 'val'}
            }
        }])
        t2_chunk = MockChunk(content="Không thể thực thi công cụ.")
        mock_stream.side_effect = [[t1_chunk], [t2_chunk]]

        messages = [{'role': 'user', 'content': 'Chạy tool lạ'}]
        chunks = list(stream_chat_ai(messages))

        tool_result_marker = next(c for c in chunks if c.startswith("__TOOL_RESULT__:"))
        self.assertIn('not found', tool_result_marker)
        self.assertIn("Không thể thực thi công cụ.", chunks)

    @patch('api.utils.ollama_client._chat_stream_with_retry')
    def test_stream_web_search_results_marker(self, mock_stream):
        """Verify web_search tool yields __SEARCH_RESULTS__ marker."""
        t1_chunk = MockChunk(tool_calls=[{
            'function': {
                'name': 'web_search',
                'arguments': {'query': 'lừa đảo telegram'}
            }
        }])
        t2_chunk = MockChunk(content="Đây là các thông tin tìm được.")
        mock_stream.side_effect = [[t1_chunk], [t2_chunk]]

        fake_search_results = [{'title': 'Cảnh báo Telegram', 'url': 'https://example.com/warn', 'snippet': 'Lua dao'}]

        messages = [{'role': 'user', 'content': 'Tìm kiếm'}]
        chunks = list(stream_chat_ai(messages, tool_dispatch={'web_search': lambda **kw: fake_search_results}))

        search_marker = next(c for c in chunks if c.startswith("__SEARCH_RESULTS__:"))
        self.assertIn('https://example.com/warn', search_marker)


class ChatAIStreamViewEndpointTest(TestCase):
    """
    Tests ChatAIStreamView SSE endpoint, database persistence, and session lifecycle.
    """

    def setUp(self):
        self.user = User.objects.create_user(username='streamuser', password='password123')
        self.async_client = AsyncClient()

    async def test_stream_endpoint_missing_message(self):
        """Sending empty payload returns SSE with error marker."""
        response = await self.async_client.post(
            reverse('chat-stream'),
            data=json.dumps({'user_message': ''}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.streaming)

        chunks = []
        async for chunk in response.streaming_content:
            chunks.append(chunk.decode('utf-8') if isinstance(chunk, bytes) else chunk)
        full_content = "".join(chunks)

        events = parse_sse_events(full_content)
        error_events = [e for e in events if 'error' in e]
        self.assertTrue(error_events)
        self.assertIn('No message provided', error_events[0]['error'])
        self.assertTrue(error_events[0].get('done'))

    @patch('api.utils.vector_db.vector_db.search', return_value=[])
    @patch('api.utils.ai_agent.AIAgent.generate_title', return_value='Hỗ trợ người dùng mới')
    @patch('api.utils.ollama_client._chat_stream_with_retry')
    @patch('api.ai_chat.views.classify_message', return_value={'suggested_action': 'CHECK_PHONE'})
    async def test_stream_guest_flow_creates_session_and_messages(self, mock_classify, mock_llm, mock_title, mock_vdb):
        """Guest user stream creates session, persists user & assistant messages, and streams SSE."""
        mock_llm.return_value = [
            MockChunk(content="Chào bạn! "),
            MockChunk(content="Tôi là trợ lý ShieldCall.")
        ]

        response = await self.async_client.post(
            reverse('chat-stream'),
            data=json.dumps({'user_message': 'Xin chào'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get('Content-Type'), 'text/event-stream')
        self.assertEqual(response.headers.get('Cache-Control'), 'no-cache, no-transform')

        chunks = []
        async for chunk in response.streaming_content:
            chunks.append(chunk.decode('utf-8') if isinstance(chunk, bytes) else chunk)
        full_content = "".join(chunks)

        events = parse_sse_events(full_content)
        chunk_texts = [e['chunk'] for e in events if 'chunk' in e]

        self.assertIn('Chào bạn! ', chunk_texts)
        self.assertIn('Tôi là trợ lý ShieldCall.', chunk_texts)

        final_events = [e for e in events if e.get('done') is True]
        self.assertEqual(len(final_events), 1)
        self.assertEqual(final_events[0].get('action_suggested'), 'CHECK_PHONE')
        session_id = final_events[0].get('session_id')
        self.assertIsNotNone(session_id)

        # Database assertions: Guest session exists and is unauthenticated
        guest_session = await ChatSession.objects.aget(id=session_id)
        self.assertIsNone(guest_session.user)

        # Verify messages persisted in DB
        messages = [m async for m in ChatMessage.objects.filter(session=guest_session).order_by('created_at')]
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0].role, 'user')
        self.assertEqual(messages[0].message, 'Xin chào')
        self.assertEqual(messages[1].role, 'assistant')
        self.assertEqual(messages[1].message, 'Chào bạn! Tôi là trợ lý ShieldCall.')

    @patch('api.utils.vector_db.vector_db.search', return_value=[])
    @patch('api.utils.ai_agent.AIAgent.generate_title', return_value='Tra cứu STK')
    @patch('api.utils.ollama_client._chat_stream_with_retry')
    @patch('api.ai_chat.views.classify_message', return_value={'suggested_action': 'NONE'})
    async def test_stream_authenticated_user_session(self, mock_classify, mock_llm, mock_title, mock_vdb):
        """Authenticated request maintains existing session and links message correctly."""
        session = await ChatSession.objects.acreate(user=self.user, title='Phiên phân tích')

        mock_llm.return_value = [MockChunk(content="Phân tích số tài khoản hoàn tất.")]

        await self.async_client.aforce_login(self.user)
        response = await self.async_client.post(
            reverse('chat-stream'),
            data=json.dumps({
                'session_id': str(session.id),
                'user_message': 'Kiểm tra tài khoản 123456'
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)

        chunks = []
        async for chunk in response.streaming_content:
            chunks.append(chunk.decode('utf-8') if isinstance(chunk, bytes) else chunk)
        full_content = "".join(chunks)

        events = parse_sse_events(full_content)
        chunk_texts = [e['chunk'] for e in events if 'chunk' in e]
        self.assertIn('Phân tích số tài khoản hoàn tất.', chunk_texts)

        final_events = [e for e in events if e.get('done') is True]
        self.assertEqual(final_events[0].get('session_id'), str(session.id))

        # Verify messages in DB
        messages = [m async for m in ChatMessage.objects.filter(session=session).order_by('created_at')]
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0].role, 'user')
        self.assertEqual(messages[0].message, 'Kiểm tra tài khoản 123456')
        self.assertEqual(messages[1].role, 'assistant')
        self.assertEqual(messages[1].message, 'Phân tích số tài khoản hoàn tất.')

    @patch('api.utils.vector_db.vector_db.search', return_value=[])
    @patch('api.utils.ai_agent.AIAgent.chat_stream')
    @patch('api.ai_chat.views.classify_message', return_value={})
    @patch('django.http.HttpRequest.get_host', return_value='app.fairspace.vn')
    async def test_stream_fairspace_host_branding(self, mock_host, mock_classify, mock_chat_stream, mock_vdb):
        """Request from fairspace host applies FairSpace branding and auto safe_mode."""
        captured_kwargs = {}

        def fake_agent_generator(user_message, **kwargs):
            captured_kwargs.update(kwargs)
            yield "Phản hồi FairSpace"

        mock_chat_stream.side_effect = fake_agent_generator

        response = await self.async_client.post(
            reverse('chat-stream'),
            data=json.dumps({'user_message': 'Tôi cần tư vấn'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)

        chunks = []
        async for chunk in response.streaming_content:
            chunks.append(chunk.decode('utf-8') if isinstance(chunk, bytes) else chunk)
        full_content = "".join(chunks)

        events = parse_sse_events(full_content)
        chunk_texts = [e['chunk'] for e in events if 'chunk' in e]
        self.assertIn('Phản hồi FairSpace', chunk_texts)

        # safe_mode should be True for fairspace
        self.assertTrue(captured_kwargs.get('safe_mode'))
