import json
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.conf import settings

from api.utils.ollama_client import (
    _format_openai_messages,
    _openai_chat_with_retry,
    _openai_chat_stream_with_retry,
    OpenAIResponseAdapter,
    OpenAIStreamChunkAdapter,
    _chat_with_retry,
    _chat_stream_with_retry,
    stream_chat_ai,
    generate_response,
)


class OpenAIBackendTest(TestCase):
    """
    Unit tests for standard OpenAI-compatible API backend (DeepSeek, etc.)
    """

    def test_default_settings_and_base_url(self):
        """Verify custom base_url and model defaults."""
        from api.utils import ollama_client
        self.assertEqual(ollama_client.OPENAI_BASE_URL, "https://api.deepseek.com")
        self.assertIn(ollama_client.DEFAULT_MODEL, ["deepseek-flash", "test"])

    def test_format_openai_messages(self):
        """Verify messages are converted to OpenAI standard format with tool_call_id."""
        input_msgs = [
            {'role': 'system', 'content': 'You are a security assistant.'},
            {'role': 'user', 'content': 'Scan this phone: +84988776655'},
            {
                'role': 'assistant',
                'content': '',
                'tool_calls': [
                    {
                        'id': 'call_123',
                        'function': {'name': 'scan_phone', 'arguments': {'phone_number': '+84988776655'}}
                    }
                ]
            },
            {'role': 'tool', 'content': '{"risk_level": "RED"}', 'tool_name': 'scan_phone'}
        ]

        formatted = _format_openai_messages(input_msgs)
        self.assertEqual(len(formatted), 4)
        self.assertEqual(formatted[0]['role'], 'system')
        self.assertEqual(formatted[1]['role'], 'user')
        self.assertEqual(formatted[2]['role'], 'assistant')
        self.assertEqual(formatted[2]['tool_calls'][0]['id'], 'call_123')
        self.assertEqual(formatted[3]['role'], 'tool')
        self.assertEqual(formatted[3]['tool_call_id'], 'call_123')

    @patch('api.utils.ollama_client.get_openai_client')
    def test_openai_chat_completion_success(self, mock_get_client):
        """Verify non-streaming chat completion converts OpenAI response to adapter."""
        mock_cli = MagicMock()
        mock_choice = MagicMock()
        mock_choice.finish_reason = 'stop'
        mock_choice.message.role = 'assistant'
        mock_choice.message.content = 'Phát hiện lừa đảo mạo danh công an.'
        mock_choice.message.reasoning_content = 'Phân tích số điện thoại...'
        mock_choice.message.tool_calls = None

        mock_usage = MagicMock()
        mock_usage.completion_tokens = 50
        mock_usage.prompt_tokens = 120

        raw_res = MagicMock()
        raw_res.choices = [mock_choice]
        raw_res.usage = mock_usage
        mock_cli.chat.completions.create.return_value = raw_res
        mock_get_client.return_value = mock_cli

        adapter = _openai_chat_with_retry(
            messages=[{'role': 'user', 'content': 'Kiểm tra SĐT'}],
            model='deepseek-flash'
        )

        self.assertIsInstance(adapter, OpenAIResponseAdapter)
        self.assertEqual(adapter.message.content, 'Phát hiện lừa đảo mạo danh công an.')
        self.assertEqual(adapter.message.thinking, 'Phân tích số điện thoại...')
        self.assertEqual(adapter.eval_count, 50)
        self.assertEqual(adapter.prompt_eval_count, 120)

    @patch('api.utils.ollama_client.get_openai_client')
    def test_openai_stream_reasoning_and_content(self, mock_get_client):
        """Verify DeepSeek reasoning_content and content streaming chunks."""
        mock_cli = MagicMock()

        # Chunk 1: Thinking / reasoning
        chunk1 = MagicMock()
        delta1 = MagicMock()
        delta1.reasoning_content = 'Đang suy nghĩ đối chiếu...'
        delta1.content = None
        delta1.tool_calls = None
        chunk1.choices = [MagicMock(delta=delta1)]

        # Chunk 2: Final response content
        chunk2 = MagicMock()
        delta2 = MagicMock()
        delta2.reasoning_content = None
        delta2.content = 'Kết quả kiểm tra: số này nguy hiểm.'
        delta2.tool_calls = None
        chunk2.choices = [MagicMock(delta=delta2)]

        mock_cli.chat.completions.create.return_value = iter([chunk1, chunk2])
        mock_get_client.return_value = mock_cli

        stream_gen = _openai_chat_stream_with_retry(
            messages=[{'role': 'user', 'content': 'Kiểm tra'}],
            model='deepseek-flash'
        )

        chunks = list(stream_gen)
        self.assertEqual(len(chunks), 2)
        self.assertEqual(chunks[0].message.thinking, 'Đang suy nghĩ đối chiếu...')
        self.assertEqual(chunks[1].message.content, 'Kết quả kiểm tra: số này nguy hiểm.')

    @patch('api.utils.ollama_client.get_openai_client')
    def test_openai_stream_tool_calls_assembly(self, mock_get_client):
        """Verify streamed tool call fragments are assembled into complete ToolCall."""
        mock_cli = MagicMock()

        tc_frag1 = MagicMock()
        tc_frag1.index = 0
        tc_frag1.id = 'call_abc'
        tc_frag1.function.name = 'scan_phone'
        tc_frag1.function.arguments = '{"phone_number":'

        tc_frag2 = MagicMock()
        tc_frag2.index = 0
        tc_frag2.id = None
        tc_frag2.function.name = None
        tc_frag2.function.arguments = ' "+84988776655"}'

        chunk1 = MagicMock()
        chunk1.choices = [MagicMock(delta=MagicMock(reasoning_content=None, content=None, tool_calls=[tc_frag1]))]

        chunk2 = MagicMock()
        chunk2.choices = [MagicMock(delta=MagicMock(reasoning_content=None, content=None, tool_calls=[tc_frag2]))]

        mock_cli.chat.completions.create.return_value = iter([chunk1, chunk2])
        mock_get_client.return_value = mock_cli

        stream_gen = _openai_chat_stream_with_retry(
            messages=[{'role': 'user', 'content': 'Tra cứu số'}],
            model='deepseek-flash'
        )

        chunks = list(stream_gen)
        self.assertEqual(len(chunks), 1)
        tool_calls = chunks[0].message.tool_calls
        self.assertEqual(len(tool_calls), 1)
        self.assertEqual(tool_calls[0].function.name, 'scan_phone')
        self.assertEqual(tool_calls[0].function.arguments, {'phone_number': '+84988776655'})
