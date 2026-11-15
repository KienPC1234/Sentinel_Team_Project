"""ShieldCall VN – Admin Dashboard Views"""
import logging
import json
import re
from django.shortcuts import redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponseForbidden, JsonResponse
from django.db import transaction
from api.core.models import LearnLesson, Article, LearnQuiz, LearnScenario, Report

logger = logging.getLogger(__name__)


def _strip_html_for_summary(text: str) -> str:
    if not text:
        return ''
    cleaned = re.sub(r'<[^>]+>', ' ', str(text))
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    return cleaned


def _extract_summary_text(raw_response) -> str:
    if raw_response is None:
        return ''

    if isinstance(raw_response, dict):
        for key in ('summary', 'tóm_tắt', 'tom_tat', 'content', 'text', 'title'):
            value = raw_response.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ''

    text = str(raw_response).strip()
    if not text:
        return ''

    try:
        parsed = json.loads(text)
    except Exception:
        parsed = None

    if parsed is None and text.startswith('```'):
        stripped = re.sub(r'^```(?:json)?\s*', '', text)
        stripped = re.sub(r'\s*```$', '', stripped).strip()
        try:
            parsed = json.loads(stripped)
        except Exception:
            parsed = None

    if parsed is None and text.startswith('{') and text.endswith('}'):
        try:
            import ast
            parsed = ast.literal_eval(text)
        except Exception:
            parsed = None

    if isinstance(parsed, dict):
        for key in ('summary', 'tóm_tắt', 'tom_tat', 'content', 'text', 'title'):
            value = parsed.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

    if isinstance(parsed, list):
        for item in parsed:
            if isinstance(item, dict):
                for key in ('summary', 'tóm_tắt', 'tom_tat', 'content', 'text', 'title'):
                    value = item.get(key)
                    if isinstance(value, str) and value.strip():
                        return value.strip()

    # regex fallback for malformed JSON / escaped payloads
    for pattern in [
        r'"summary"\s*:\s*"([\s\S]*?)"\s*(?:,|})',
        r'"tóm_tắt"\s*:\s*"([\s\S]*?)"\s*(?:,|})',
        r'"tom_tat"\s*:\s*"([\s\S]*?)"\s*(?:,|})',
        r"'summary'\s*:\s*'([\s\S]*?)'\s*(?:,|})",
        r"'tóm_tắt'\s*:\s*'([\s\S]*?)'\s*(?:,|})",
    ]:
        m = re.search(pattern, text)
        if m and m.group(1).strip():
            return m.group(1).strip()

    # If still object-like, avoid leaking raw JSON into summary field
    if (text.startswith('{') and text.endswith('}')) or (text.startswith('[') and text.endswith(']')):
        return ''

    return text


def _generate_summary_ai(title: str, content: str) -> str:
    """Generate short summary using SMALL_MODEL; returns empty string on failure."""
    source = _strip_html_for_summary(content)
    if not source:
        return ''
    try:
        from django.conf import settings
        from api.utils.ollama_client import generate_response

        small_model = getattr(settings, 'SMALL_MODEL', None) or getattr(settings, 'LLM_MODEL', 'ministral-3:14b-cloud')
        summary_schema = {
            "type": "object",
            "properties": {
                "summary": {"type": "string"}
            },
            "required": ["summary"]
        }
        prompt = f"""Tạo tóm tắt súc tích bằng tiếng Việt cho bài viết/bài học sau.

TIÊU ĐỀ: {title or ''}
NỘI DUNG:
{source[:4000]}

YÊU CẦU:
- 2-4 câu ngắn, tối đa 420 ký tự
- Dễ hiểu, trung lập, không emoji
- KHÔNG trả về JSON thô trong trường summary (không object lồng, không key khác)
"""
        raw_summary = generate_response(
            prompt=prompt,
            model=small_model,
            system_prompt='Trả về JSON thuần theo schema. Không markdown, không code block.',
            format_schema=summary_schema,
            tools=[],
            max_tokens=1200,
            skip_filter=True,
        ) or ''
        summary = _extract_summary_text(raw_summary)
        summary = re.sub(r'\s+', ' ', summary).strip().strip('"')
        return summary[:420]
    except Exception as exc:
        logger.warning(f"Summary generation failed: {exc}")
        return ''

def admin_required(view_func):
    """Decorator to require staff (Admin) or super admin"""
    @login_required
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_staff or (hasattr(request.user, 'profile') and request.user.profile.is_super_admin):
            return view_func(request, *args, **kwargs)
        return HttpResponseForbidden("Bạn không có quyền truy cập trang này.")
    return _wrapped_view


@admin_required
def approve_report(request, report_id):
    """Approve a community report"""
    report = get_object_or_404(Report, id=report_id)
    report.status = 'approved'
    report.moderator = request.user
    report.save(update_fields=['status', 'moderator'])
    
    # Notify user via email & push notification if registered
    if report.reporter:
        from api.utils.email_utils import send_report_outcome_email
        send_report_outcome_email(report.reporter, "website/tài khoản", report.target_value, 'approved')

        from api.utils.push_service import push_service
        push_service.send_push(
            report.reporter.id,
            'Báo cáo đã được chấp thuận',
            f'Báo cáo #{report_id} về {report.target_value} đã được chấp thuận. Cảm ơn bạn đã góp phần bảo vệ cộng đồng!',
            url='/my-reports/',
            notification_type='success'
        )
    
    messages.success(request, f"Đã chấp thuận báo cáo #{report_id}.")
    if request.headers.get('accept') == 'application/json' or request.content_type == 'application/json':
        return JsonResponse({'status': 'success', 'message': f'Đã chấp thuận báo cáo #{report_id}.'})
    return redirect('/admin-cp/reports/')

@admin_required
def reject_report(request, report_id):
    """Reject a community report"""
    report = get_object_or_404(Report, id=report_id)
    report.status = 'rejected'
    report.moderator = request.user
    report.save(update_fields=['status', 'moderator'])
    
    # Notify user via email & push notification if registered
    if report.reporter:
        from api.utils.email_utils import send_report_outcome_email
        send_report_outcome_email(report.reporter, "website/tài khoản", report.target_value, 'rejected')

        from api.utils.push_service import push_service
        push_service.send_push(
            report.reporter.id,
            'Báo cáo đã bị từ chối',
            f'Báo cáo #{report_id} về {report.target_value} đã bị từ chối. Vui lòng kiểm tra lại thông tin.',
            url='/my-reports/',
            notification_type='warning'
        )
    
    messages.info(request, f"Đã từ chối báo cáo #{report_id}.")
    if request.headers.get('accept') == 'application/json' or request.content_type == 'application/json':
        return JsonResponse({'status': 'success', 'message': f'Đã từ chối báo cáo #{report_id}.'})
    return redirect('/admin-cp/reports/')

@admin_required
def analyze_report_ai(request, report_id):
    """Run/re-run AI analysis on a report"""
    from api.utils.ollama_client import analyze_text_for_scam
    from api.utils.media_utils import extract_ocr_text
    import traceback
    
    report = get_object_or_404(Report, id=report_id)
    
    try:
        # Re-run OCR if evidence exists and no OCR text
        if report.evidence_file and not report.ocr_text:
            try:
                ocr_text = extract_ocr_text(report.evidence_file)
                if ocr_text:
                    report.ocr_text = ocr_text
                    report.save()
            except Exception as e:
                logger.error(f"[AdminReportOCR] Error: {e}")
        
        # Build context
        full_context = f"Target Type: {report.target_type}\n"
        full_context += f"Target Value: {report.target_value}\n"
        full_context += f"Scam Type: {report.scam_type}\n"
        full_context += f"Severity: {report.severity}\n"
        full_context += f"Description: {report.description}\n"
        if report.scammer_name:
            full_context += f"Scammer Name: {report.scammer_name}\n"
        if report.scammer_phone:
            full_context += f"Scammer Phone: {report.scammer_phone}\n"
        if report.scammer_bank_account:
            full_context += f"Scammer Bank: {report.scammer_bank_name} - {report.scammer_bank_account}\n"
        if report.ocr_text:
            full_context += f"OCR Evidence Text: {report.ocr_text}\n"
        
        # Admin mở kiểm duyệt = hành động phân tích rõ ràng.
        analysis = analyze_text_for_scam(full_context, external_consent=True)
        report.ai_analysis = analysis
        report.save()
        
        return JsonResponse({
            'status': 'success',
            'message': 'AI phân tích hoàn tất',
            'ai_analysis': analysis
        })
    except Exception as e:
        logger.error(f"[AdminReportAI] Error: {e}\n{traceback.format_exc()}")
        return JsonResponse({
            'status': 'error',
            'message': f'Lỗi phân tích AI: {str(e)}'
        }, status=500)

@admin_required
def update_report_note(request, report_id):
    """Update moderation note for a report"""
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Method not allowed'}, status=405)
    
    report = get_object_or_404(Report, id=report_id)
    
    try:
        data = json.loads(request.body)
        note = data.get('note', '').strip()
    except (json.JSONDecodeError, AttributeError):
        note = request.POST.get('note', '').strip()
    
    report.moderation_note = note
    report.moderator = request.user
    report.save()
    
    return JsonResponse({
        'status': 'success',
        'message': 'Đã cập nhật ghi chú kiểm duyệt'
    })


@admin_required
def magic_create_article_api(request):
    """AI API to generate article structure — dispatched to Celery with WS progress."""
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Only POST allowed'}, status=405)
        
    try:
        data = json.loads(request.body)
        raw_text = data.get('text', '').strip()
        sources_raw = data.get('sources', [])

        if isinstance(sources_raw, str):
            sources = [line.strip() for line in sources_raw.split('\n') if line.strip()]
        elif isinstance(sources_raw, list):
            sources = [str(item).strip() for item in sources_raw if str(item).strip()]
        else:
            sources = []
        
        if not raw_text:
            return JsonResponse({'status': 'error', 'message': 'Empty text'}, status=400)
        if not sources:
            return JsonResponse({'status': 'error', 'message': 'Vui lòng thêm ít nhất 1 nguồn trích dẫn'}, status=400)
        
        import uuid
        task_id = uuid.uuid4().hex[:12]
        
        from api.core.tasks import magic_create_article_task
        magic_create_article_task.delay(task_id, raw_text, sources, request.user.id)
        
        return JsonResponse({'status': 'pending', 'task_id': task_id})
        
    except Exception as e:
        logger.error(f"Error in magic_create_article_api: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@admin_required
def magic_save_article_api(request):
    """API to save the AI-generated article (news only, no quiz/scenario)."""
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Only POST allowed'}, status=405)
        
    try:
        data = json.loads(request.body)
        
        with transaction.atomic():
            summary = (data.get('summary') or '').strip()
            if not summary:
                summary = _generate_summary_ai(data.get('title', ''), data.get('content', ''))
            article = Article.objects.create(
                title=data.get('title'),
                summary=summary,
                content=data.get('content'),
                category=data.get('category', 'news'),
                is_published=False
            )
                
        return JsonResponse({'status': 'success', 'article_id': article.id})
        
    except Exception as e:
        logger.error(f"Error in magic_save_article_api: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@admin_required
def magic_create_lesson_api(request):
    """AI API to generate lesson structure — dispatched to Celery with WS progress."""
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Only POST allowed'}, status=405)
        
    try:
        data = json.loads(request.body)
        raw_text = data.get('text', '').strip()
        include_quiz = bool(data.get('include_quiz', True))
        include_scenario = bool(data.get('include_scenario', True))
        try:
            quiz_count = int(data.get('quiz_count', 5))
        except (TypeError, ValueError):
            quiz_count = 5
        try:
            scenario_steps = int(data.get('scenario_steps', 8))
        except (TypeError, ValueError):
            scenario_steps = 8
        quiz_count = max(1, min(quiz_count, 20))
        scenario_steps = max(4, min(scenario_steps, 30))
        
        if not raw_text:
            return JsonResponse({'status': 'error', 'message': 'Empty text'}, status=400)
        
        import uuid
        task_id = uuid.uuid4().hex[:12]
        
        from api.core.tasks import magic_create_lesson_task
        magic_create_lesson_task.delay(
            task_id,
            raw_text,
            include_quiz,
            include_scenario,
            quiz_count,
            scenario_steps,
            request.user.id,
        )
        
        return JsonResponse({'status': 'pending', 'task_id': task_id})
        
    except Exception as e:
        logger.error(f"Error in magic_create_lesson_api: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@admin_required
def generate_summary_api(request):
    """Generate short summary from title/content via SMALL_MODEL."""
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Only POST allowed'}, status=405)

    try:
        data = json.loads(request.body)
        title = (data.get('title') or '').strip()
        content = data.get('content') or ''
        summary = _generate_summary_ai(title, content)
        if not summary:
            return JsonResponse({'status': 'error', 'message': 'Không tạo được tóm tắt'}, status=400)
        return JsonResponse({'status': 'success', 'summary': summary})
    except Exception as exc:
        logger.error(f"Error in generate_summary_api: {exc}")
        return JsonResponse({'status': 'error', 'message': str(exc)}, status=500)

@admin_required
def magic_save_lesson_api(request):
    """API to save the AI-generated lesson, multiple quizzes and scenario"""
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Only POST allowed'}, status=405)
        
    try:
        data = json.loads(request.body)
        
        with transaction.atomic():
            summary = (data.get('summary') or '').strip()
            if not summary:
                summary = _generate_summary_ai(data.get('title', ''), data.get('content', ''))
            # 1. Create Lesson
            lesson = LearnLesson.objects.create(
                title=data.get('title'),
                summary=summary,
                content=data.get('content'),
                category=data.get('category', 'guide'),
                is_published=False # Start as draft
            )
            
            # 2. Create Quizzes (multiple)
            quizzes_data = data.get('quizzes', [])
            # Backward compat: single quiz
            if not quizzes_data and data.get('quiz'):
                quizzes_data = [data['quiz']]
            
            for quiz_data in quizzes_data:
                if quiz_data and quiz_data.get('question'):
                    LearnQuiz.objects.create(
                        lesson=lesson,
                        question=quiz_data.get('question'),
                        options=quiz_data.get('options', []),
                        correct_answer=quiz_data.get('correct_answer'),
                        explanation=quiz_data.get('explanation', '')
                    )
            
            # 3. Create Scenario
            scenario_data = data.get('scenario')
            if scenario_data:
                content_json = scenario_data.get('content_json') if isinstance(scenario_data, dict) else None
                steps = []
                if isinstance(content_json, dict):
                    raw_steps = content_json.get('steps', [])
                    if isinstance(raw_steps, list):
                        steps = [s for s in raw_steps if isinstance(s, dict) and str(s.get('text', '')).strip()]
                if steps:
                    LearnScenario.objects.create(
                        lesson=lesson,
                        title=scenario_data.get('title'),
                        description=scenario_data.get('description'),
                        content={'steps': steps},
                    )
                
        return JsonResponse({'status': 'success', 'lesson_id': lesson.id})
        
    except Exception as e:
        logger.error(f"Error in magic_save_lesson_api: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

