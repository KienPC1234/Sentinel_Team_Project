"""ShieldCall VN – Admin Dashboard Views"""
import logging
import json
import re
from django.shortcuts import redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.db.models import Count, F
from django.http import HttpResponseForbidden
from api.core.models import (
    LearnLesson, ForumPost, Article, LearnQuiz, LearnScenario, BankAccount, Domain,
    Report, ScanEvent, ForumPostReport, ForumCommentReport, ScamType, ArticleCategory
)
from django.db.models import Q
from api.core.forms import LearnLessonForm, ArticleForm, LearnScenarioForm
from django.http import HttpResponseForbidden, JsonResponse
from django.db import transaction
from django.utils import timezone
from django.core.paginator import Paginator
from datetime import timedelta
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

User = get_user_model()
logger = logging.getLogger(__name__)


def _broadcast_forum_live_event(event_name: str, payload: dict):
    try:
        channel_layer = get_channel_layer()
        if not channel_layer:
            return
        async_to_sync(channel_layer.group_send)(
            'forum_live',
            {
                'type': 'forum_live_event',
                'event': event_name,
                'payload': payload or {},
                'timestamp': timezone.now().isoformat(),
            }
        )
    except Exception as exc:
        logger.warning(f"Forum live broadcast failed ({event_name}): {exc}")


def _soft_hide_post(post, reason: str = ''):
    note = _strip_html_for_summary(reason or '')
    prefix = '[NỘI DUNG ĐÃ TẠM ẨN BỞI KIỂM DUYỆT VIÊN]'
    replacement = f"{prefix}\n\nLý do: {note[:280]}" if note else f"{prefix}\n\nĐang chờ xử lý thủ công."
    changed_fields = []
    if not str(post.content or '').startswith(prefix):
        post.content = replacement
        changed_fields.append('content')
    if not post.is_locked:
        post.is_locked = True
        changed_fields.append('is_locked')
    if changed_fields:
        post.save(update_fields=changed_fields)


def _soft_hide_comment(comment, reason: str = ''):
    note = _strip_html_for_summary(reason or '')
    prefix = '[BÌNH LUẬN ĐÃ TẠM ẨN BỞI KIỂM DUYỆT VIÊN]'
    replacement = f"{prefix} Lý do: {note[:220]}" if note else f"{prefix} Đang chờ xử lý thủ công."
    if not str(comment.content or '').startswith(prefix):
        comment.content = replacement
        comment.save(update_fields=['content'])


def _paginate_queryset(request, queryset, per_page=20):
    paginator = Paginator(queryset, per_page)
    page_number = request.GET.get('page') or 1
    page_obj = paginator.get_page(page_number)
    query_params = request.GET.copy()
    query_params.pop('page', None)
    return page_obj, query_params.urlencode()


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

def super_admin_required(view_func):
    """Decorator to require super admin role"""
    @login_required
    def _wrapped_view(request, *args, **kwargs):
        if hasattr(request.user, 'profile') and request.user.profile.is_super_admin:
            return view_func(request, *args, **kwargs)
        return HttpResponseForbidden("Bạn không có quyền truy cập trang này. Chỉ Super Admin mới có quyền.")
    return _wrapped_view

def admin_required(view_func):
    """Decorator to require staff (Admin) or super admin"""
    @login_required
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_staff or (hasattr(request.user, 'profile') and request.user.profile.is_super_admin):
            return view_func(request, *args, **kwargs)
        return HttpResponseForbidden("Bạn không có quyền truy cập trang này.")
    return _wrapped_view



@admin_required
def admin_stats_api(request):
    """API for real-time dashboard stats and charts"""
    now = timezone.now()
    seven_days_ago = now - timedelta(days=7)
    
    try:
        # Simple count-up stats
        stats = {
            'users': User.objects.count(),
            'reports': Report.objects.filter(status='pending').count(),
            'scans': ScanEvent.objects.count(),
            'forum_reports': ForumPostReport.objects.filter(status='pending').count() + ForumCommentReport.objects.filter(status='pending').count(),
        }
        
        # Chart data (last 7 days)
        chart_data = {
            'labels': [(seven_days_ago + timedelta(days=i)).strftime('%d/%m') for i in range(8)],
            'reports': [],
            'scans': []
        }
        
        for i in range(8):
            day = (seven_days_ago + timedelta(days=i)).date()
            report_count = Report.objects.filter(created_at__date=day).count()
            scan_count = ScanEvent.objects.filter(created_at__date=day).count()
            chart_data['reports'].append(report_count)
            chart_data['scans'].append(scan_count)
            
        return JsonResponse({
            'status': 'success',
            'stats': stats,
            'charts': chart_data
        })
    except Exception as e:
        logger.error(f"Error in admin_stats_api: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)



@admin_required
def forum_report_action(request, report_type, report_id):
    """Approve/reject/analyze forum reports. Returns JSON."""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    action = request.POST.get('action')
    if not action and request.body:
        try:
            body_data = json.loads(request.body)
            if isinstance(body_data, dict):
                action = body_data.get('action')
        except (json.JSONDecodeError, UnicodeDecodeError):
            action = None
    if not action:
        return JsonResponse({'error': 'Missing action'}, status=400)

    try:
        if report_type == 'post':
            report = ForumPostReport.objects.select_related('post', 'post__author', 'reporter').get(id=report_id)
        else:
            report = ForumCommentReport.objects.select_related('comment', 'comment__author', 'reporter').get(id=report_id)

        if action == 'approve':
            report.status = 'approved'
            report.is_resolved = True
            report.save()
            if report_type == 'post' and hasattr(report, 'post'):
                _soft_hide_post(report.post, report.reason)
                _broadcast_forum_live_event('post_moderated', {
                    'post_id': report.post.id,
                    'report_id': report.id,
                    'source': 'admin_moderation',
                    'action': 'hidden',
                })
            elif report_type == 'comment' and hasattr(report, 'comment'):
                _soft_hide_comment(report.comment, report.reason)
                _broadcast_forum_live_event('comment_moderated', {
                    'post_id': report.comment.post_id,
                    'comment_id': report.comment.id,
                    'report_id': report.id,
                    'source': 'admin_moderation',
                    'action': 'hidden',
                })
            return JsonResponse({'status': 'ok', 'message': f'Đã chấp thuận báo cáo #{report_id}'})

        elif action == 'reject':
            report.status = 'rejected'
            report.is_resolved = True
            report.save()
            return JsonResponse({'status': 'ok', 'message': f'Đã từ chối báo cáo #{report_id}'})

        elif action == 'analyze':
            if report_type == 'post':
                from api.core.tasks import process_forum_report
                process_forum_report.delay(report_id)
            else:
                from api.core.tasks import process_forum_comment_report
                process_forum_comment_report.delay(report_id)
            return JsonResponse({'status': 'ok', 'message': f'Đã gửi phân tích AI cho báo cáo #{report_id}'})

        else:
            return JsonResponse({'error': 'Unknown action'}, status=400)

    except (ForumPostReport.DoesNotExist, ForumCommentReport.DoesNotExist):
        return JsonResponse({'error': 'Báo cáo không tồn tại'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@admin_required
def forum_post_admin_action(request, post_id):
    """Admin actions on forum posts: delete, pin/unpin. Returns JSON."""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    action = request.POST.get('action')
    if not action and request.body:
        try:
            body_data = json.loads(request.body)
            if isinstance(body_data, dict):
                action = body_data.get('action')
        except (json.JSONDecodeError, UnicodeDecodeError):
            action = None
    try:
        post = ForumPost.objects.get(id=post_id)

        if action == 'delete':
            title = post.title
            post.delete()
            return JsonResponse({'status': 'ok', 'message': f'Đã xóa bài viết: {title}'})

        elif action == 'pin':
            post.is_pinned = not post.is_pinned
            post.save(update_fields=['is_pinned'])
            state = 'ghim' if post.is_pinned else 'bỏ ghim'
            return JsonResponse({'status': 'ok', 'message': f'Đã {state} bài viết', 'is_pinned': post.is_pinned})

        elif action == 'lock':
            post.is_locked = not post.is_locked
            post.save(update_fields=['is_locked'])
            state = 'khóa' if post.is_locked else 'mở khóa'
            return JsonResponse({'status': 'ok', 'message': f'Đã {state} bài viết', 'is_locked': post.is_locked})

        else:
            return JsonResponse({'error': 'Unknown action'}, status=400)

    except ForumPost.DoesNotExist:
        return JsonResponse({'error': 'Bài viết không tồn tại'}, status=404)


@admin_required
def forum_ban_action(request):
    """Ban or unban a user from the forum. Returns JSON."""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    action = data.get('action')
    username = data.get('username')

    if not action or not username:
        return JsonResponse({'error': 'Missing action or username'}, status=400)

    try:
        from api.core.models import ForumBan
        target_user = User.objects.get(username=username)

        if action == 'ban':
            reason = data.get('reason', 'Vi phạm nội quy diễn đàn')
            ban_type = data.get('ban_type', 'temporary')
            try:
                days = int(data.get('days', 7))
            except (TypeError, ValueError):
                return JsonResponse({'error': 'Số ngày ban không hợp lệ.'}, status=400)
            if ban_type != 'permanent' and days <= 0:
                return JsonResponse({'error': 'Số ngày ban phải lớn hơn 0.'}, status=400)

            # Deactivate existing bans
            ForumBan.objects.filter(user=target_user, is_active=True).update(is_active=False)

            from django.utils import timezone
            from datetime import timedelta
            expires = None
            if ban_type == 'temporary':
                expires = timezone.now() + timedelta(days=days)

            ForumBan.objects.create(
                user=target_user,
                banned_by=request.user,
                reason=reason,
                ban_type=ban_type,
                expires_at=expires,
            )
            return JsonResponse({'status': 'ok', 'message': f'Đã cấm {username} khỏi diễn đàn'})

        elif action == 'unban':
            ForumBan.objects.filter(user=target_user, is_active=True).update(is_active=False)
            return JsonResponse({'status': 'ok', 'message': f'Đã gỡ cấm {username}'})

        else:
            return JsonResponse({'error': 'Unknown action'}, status=400)

    except User.DoesNotExist:
        return JsonResponse({'error': 'Người dùng không tồn tại'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@admin_required
def forum_moderator_action(request):
    """Promote or demote a user as forum moderator (is_staff). Returns JSON."""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    action = data.get('action')  # 'promote' or 'demote'
    username = data.get('username')

    if not action or not username:
        return JsonResponse({'error': 'Missing action or username'}, status=400)

    try:
        target_user = User.objects.get(username=username)

        if target_user == request.user:
            return JsonResponse({'error': 'Không thể thay đổi quyền của chính mình'}, status=400)

        if target_user.is_superuser:
            return JsonResponse({'error': 'Không thể thay đổi quyền của Super Admin'}, status=400)

        if action == 'promote':
            target_user.is_staff = True
            target_user.save(update_fields=['is_staff'])
            return JsonResponse({'status': 'ok', 'message': f'Đã bổ nhiệm {username} làm Kiểm duyệt viên', 'is_staff': True})

        elif action == 'demote':
            target_user.is_staff = False
            target_user.save(update_fields=['is_staff'])
            return JsonResponse({'status': 'ok', 'message': f'Đã gỡ quyền Kiểm duyệt viên của {username}', 'is_staff': False})

        else:
            return JsonResponse({'error': 'Unknown action'}, status=400)

    except User.DoesNotExist:
        return JsonResponse({'error': 'Người dùng không tồn tại'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)



@super_admin_required
def toggle_admin_role(request, user_id):
    """Promote/Demote a user to Admin (Staff)"""
    target_user = get_object_or_404(User, id=user_id)
    if target_user == request.user:
        messages.error(request, "Bạn không thể tự thay đổi quyền của mình.")
    else:
        target_user.is_staff = not target_user.is_staff
        target_user.save()
        role = "Admin" if target_user.is_staff else "User"
        messages.success(request, f"Đã cập nhật vai trò cho {target_user.username} thành {role}.")
    return redirect('/admin-cp/users/')


@super_admin_required
def admin_user_action(request, user_id):
    """Advanced user controls for Super Admin dashboard."""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    target_user = get_object_or_404(User.objects.select_related('profile'), id=user_id)
    if target_user == request.user:
        return JsonResponse({'error': 'Không thể thao tác trên chính tài khoản của bạn.'}, status=400)

    try:
        data = json.loads(request.body or '{}')
    except Exception:
        data = {}
    action = (data.get('action') or '').strip()

    try:
        if action == 'toggle_active':
            if target_user.is_superuser:
                return JsonResponse({'error': 'Không thể khoá/mở khóa Superuser.'}, status=400)
            target_user.is_active = not target_user.is_active
            target_user.save(update_fields=['is_active'])
            return JsonResponse({
                'status': 'ok',
                'message': f"Đã {'mở khóa' if target_user.is_active else 'khóa'} tài khoản {target_user.username}.",
                'is_active': target_user.is_active,
            })

        if action == 'reset_rank':
            if hasattr(target_user, 'profile'):
                target_user.profile.rank_points = 0
                target_user.profile.save(update_fields=['rank_points'])
                return JsonResponse({'status': 'ok', 'message': f'Đã reset điểm uy tín cho {target_user.username}.'})
            return JsonResponse({'error': 'Người dùng chưa có hồ sơ profile.'}, status=400)

        return JsonResponse({'error': 'Unknown action'}, status=400)
    except Exception as exc:
        logger.error(f"admin_user_action error: {exc}")
        return JsonResponse({'error': str(exc)}, status=500)


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
        
        analysis = analyze_text_for_scam(full_context)
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
def delete_lesson(request, lesson_id):
    """Delete a Learn Lesson"""
    lesson = get_object_or_404(LearnLesson, id=lesson_id)
    lesson.delete()
    messages.success(request, f"Đã xóa bài học '{lesson.title}'.")
    return redirect('/admin-cp/learn/')

@admin_required
def delete_article(request, article_id):
    """Delete an Article"""
    article = get_object_or_404(Article, id=article_id)
    article.delete()
    messages.success(request, f"Đã xóa tin tức '{article.title}'.")
    return redirect('/admin-cp/articles/')

@admin_required
def notify_lesson_email(request, lesson_id):
    """Send email and push notifications to users about a new lesson"""
    lesson = get_object_or_404(LearnLesson, id=lesson_id)

    # Get all active users with email
    active_users = User.objects.filter(is_active=True)
    user_emails = list(active_users.exclude(email__isnull=True).exclude(email='').values_list('email', flat=True))
    user_emails = sorted(set(user_emails))
    
    if not user_emails:
        messages.warning(request, "Không có người dùng nào để gửi thông báo.")
        return redirect('/admin-cp/learn/')
        
    from api.utils.email_utils import send_new_lesson_email
    lesson_url = request.build_absolute_uri(f"/learn/lesson/{lesson.slug}/")

    # Send email notifications
    sent_email_count = send_new_lesson_email(user_emails, lesson.title, lesson_url)
    
    # Send push notifications to all active users
    push_count = 0
    try:
        from api.utils.push_service import PushNotificationService
        for user in active_users:
            try:
                PushNotificationService.send_push(
                    user_id=user.id,
                    title='📚 Bài học mới trên ShieldCall',
                    message=f'{lesson.title}',
                    url=f'/learn/lesson/{lesson.slug}/',
                    notification_type='info'
                )
                push_count += 1
            except Exception:
                pass
        logger.info(f"Sent push notifications to {push_count} users for lesson '{lesson.title}'")
    except Exception as e:
        logger.error(f"Error sending push notifications for lesson: {e}")

    if sent_email_count > 0:
        messages.success(request, f"Đã gửi email ({sent_email_count}) và push ({push_count}) cho người dùng.")
    else:
        messages.warning(request, f"Không gửi được email (0/{len(user_emails)}). Push đã gửi: {push_count}.")
    return redirect('/admin-cp/learn/')





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





@admin_required
def delete_scenario(request, scenario_id):
    """Delete a scenario"""
    scenario = get_object_or_404(LearnScenario, id=scenario_id)
    article_id = scenario.article.id if scenario.article else None
    scenario.delete()
    messages.success(request, "Kịch bản đã được xóa.")
    
    if article_id:
        return redirect(f'/admin-cp/articles/{article_id}/edit/')
    return redirect('/admin-cp/scenarios/')

