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


# ── Helper cho giao thức mới (mỗi event có `type`) ──
def delta_texts(events):
    """Text của các event delta."""
    return [e.get('text', '') for e in events if e.get('type') == 'delta']


def done_events(events):
    return [e for e in events if e.get('type') == 'done' or e.get('done') is True]


def error_events(events):
    return [e for e in events if e.get('type') == 'error' or 'error' in e]


# ── Helper cho event do stream_chat_ai phát ra (list[dict]) ──
def ev_texts(events):
    return [e.get('text', '') for e in events if isinstance(e, dict) and e.get('type') == 'delta']


def ev_of(events, etype):
    return [e for e in events if isinstance(e, dict) and e.get('type') == etype]


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

        self.assertIn("Chào bạn, ", ev_texts(chunks))
        self.assertIn("tôi có thể giúp gì?", ev_texts(chunks))
        self.assertFalse(ev_of(chunks, 'tool_calls'))

    @patch('api.utils.ollama_client._chat_stream_with_retry')
    def test_stream_thinking_phases(self, mock_stream):
        """Verify thinking chunks yield status transition and think markers."""
        chunk_think = MockChunk(thinking="Đang phân tích số điện thoại...")
        chunk_answer = MockChunk(content="Số này an toàn.")
        mock_stream.return_value = [chunk_think, chunk_answer]

        messages = [{'role': 'user', 'content': 'Check số này'}]
        chunks = list(stream_chat_ai(messages))

        statuses = [e.get('value') for e in ev_of(chunks, 'status')]
        self.assertIn('thinking', statuses)
        self.assertIn('answering', statuses)
        self.assertIn("Đang phân tích số điện thoại...", [e.get('text') for e in ev_of(chunks, 'thinking')])
        self.assertIn("Số này an toàn.", ev_texts(chunks))

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

        # Assert tool_call / tool_result events yielded to frontend
        tool_call_ev = ev_of(chunks, 'tool_calls')[0]
        self.assertIn('scan_phone', json.dumps(tool_call_ev.get('calls')))

        tool_result_ev = ev_of(chunks, 'tool_result')[-1]
        self.assertEqual(tool_result_ev.get('status'), 'done')
        self.assertIn('SAFE', json.dumps(tool_result_ev.get('result')))

        # Assert messages updated for multi-turn
        assistant_turn = next(m for m in messages if m.get('role') == 'assistant')
        self.assertTrue(assistant_turn.get('tool_calls'))

        tool_turn = next(m for m in messages if m.get('role') == 'tool')
        self.assertEqual(tool_turn.get('tool_name'), 'scan_phone')

        # Final answer yielded
        self.assertIn("Số điện thoại 0988776655 đã được xác minh.", ev_texts(chunks))

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

        tool_result_ev = ev_of(chunks, 'tool_result')[-1]
        self.assertIn('not found', json.dumps(tool_result_ev.get('result')))
        self.assertIn("Không thể thực thi công cụ.", ev_texts(chunks))

    @patch('api.utils.ollama_client._chat_stream_with_retry')
    def test_stream_web_search_results_marker(self, mock_stream):
        """Verify web_search tool yields a metadata event with web_search results."""
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

        search_ev = ev_of(chunks, 'metadata')[0]
        self.assertIn('https://example.com/warn', json.dumps(search_ev.get('metadata')))


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
        errs = error_events(events)
        self.assertTrue(errs)
        self.assertIn('No message provided', errs[0].get('message') or errs[0].get('error'))
        self.assertTrue(done_events(events))

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
        chunk_texts = delta_texts(events)

        self.assertIn('Chào bạn! ', chunk_texts)
        self.assertIn('Tôi là trợ lý ShieldCall.', chunk_texts)

        final_events = done_events(events)
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
    @patch('api.utils.ai_agent.AIAgent.generate_title', return_value='Kiểm tra an toàn')
    @patch('api.utils.ollama_client._chat_stream_with_retry')
    @patch('api.ai_chat.views.classify_message', return_value={'suggested_action': 'NONE'})
    async def test_stream_emits_structured_guardrail(self, mock_classify, mock_llm, mock_title, mock_vdb):
        """Luồng chat phải phát event `guardrail` có cấu trúc + lưu vào metadata (góp ý #1)."""
        mock_llm.return_value = [MockChunk(content="Yên tâm, số này 100% an toàn.")]

        response = await self.async_client.post(
            reverse('chat-stream'),
            data=json.dumps({'user_message': 'Kiểm tra số 0912345678'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)

        chunks = []
        async for chunk in response.streaming_content:
            chunks.append(chunk.decode('utf-8') if isinstance(chunk, bytes) else chunk)
        events = parse_sse_events("".join(chunks))

        guard_events = [e for e in events if e.get('type') == 'guardrail']
        self.assertEqual(len(guard_events), 1)
        guard = guard_events[0]['guardrail']
        self.assertEqual(guard['tier'], 'INSUFFICIENT')
        self.assertFalse(guard['is_conclusive'])
        self.assertTrue(guard['answer_asserts_absolute_safety'])
        self.assertTrue(any('AI' in c for c in guard['cautions']))
        self.assertTrue(guard['official_channels'])

        # Guardrail phải được lưu cùng tin nhắn trợ lý để còn hiển thị lại.
        session_id = done_events(events)[0].get('session_id')
        session = await ChatSession.objects.aget(id=session_id)
        assistant = await ChatMessage.objects.aget(session=session, role='assistant')
        self.assertEqual((assistant.metadata or {}).get('guardrail', {}).get('tier'), 'INSUFFICIENT')

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
        chunk_texts = delta_texts(events)
        self.assertIn('Phân tích số tài khoản hoàn tất.', chunk_texts)

        final_events = done_events(events)
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
            yield {"type": "delta", "text": "Phản hồi FairSpace"}

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
        self.assertIn('Phản hồi FairSpace', delta_texts(events))

        # safe_mode should be True for fairspace
        self.assertTrue(captured_kwargs.get('safe_mode'))
