import logging
from celery.result import AsyncResult
from django.core.cache import cache
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from api.core.tasks import generate_scam_iq_exam_task, score_scamiq_responses_task
from api.core.models import ScamIQAttempt

logger = logging.getLogger(__name__)




class ScamIQStartView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        task = generate_scam_iq_exam_task.delay(user_id=request.user.id)
        return Response({
            'task_id': task.id,
            'status': 'PENDING',
            'message': 'Đang khởi tạo bài kiểm tra AI 30 câu hỏi...',
        })


class ScamIQStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, task_id):
        result = AsyncResult(task_id)

        if result.state in {'PENDING', 'RETRY', 'STARTED'}:
            return Response({'status': result.state, 'ready': False})

        if result.state == 'FAILURE':
            return Response({
                'status': 'FAILURE',
                'ready': False,
                'error': 'Không thể tạo bài kiểm tra lúc này. Vui lòng thử lại sau.',
            }, status=500)

        payload = result.result if isinstance(result.result, dict) else {}
        exam_id = payload.get('exam_id')
        if not exam_id:
            return Response({'status': 'FAILURE', 'ready': False, 'error': 'Thiếu dữ liệu đề kiểm tra.'}, status=500)

        exam = cache.get(f'scam_iq_exam:{exam_id}') or {}
        if not exam:
            return Response({'status': 'FAILURE', 'ready': False, 'error': 'Đề kiểm tra đã hết hạn.'}, status=410)

        owner_id = exam.get('user_id')
        if owner_id and owner_id != request.user.id:
            return Response({'error': 'Bạn không có quyền truy cập đề này.'}, status=403)

        return Response({
            'status': 'SUCCESS',
            'ready': True,
            'exam_id': exam_id,
            'exam_title': exam.get('exam_title'),
            'intro': exam.get('intro'),
            'max_score': exam.get('max_score', 300),
            'total_questions': len(exam.get('public_questions') or []),
            'questions': exam.get('public_questions') or [],
        })


class ScamIQSubmitView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        exam_id = str(request.data.get('exam_id') or '').strip()
        answers = request.data.get('answers') or {}
        if not exam_id:
            return Response({'error': 'Thiếu exam_id.'}, status=400)

        exam = cache.get(f'scam_iq_exam:{exam_id}') or {}
        if not exam:
            return Response({'error': 'Bài kiểm tra đã hết hạn. Vui lòng tạo bộ câu hỏi mới.'}, status=410)

        owner_id = exam.get('user_id')
        if owner_id and owner_id != request.user.id:
            return Response({'error': 'Bạn không có quyền nộp bài này.'}, status=403)

        def _normalize_text(value) -> str:
            return str(value or '').strip().lower()

        answer_map = {}
        if isinstance(answers, dict):
            for key, value in answers.items():
                qid = str(key).strip()
                if isinstance(value, list):
                    picks = [str(x).strip().upper() for x in value if str(x).strip()]
                    answer_map[qid] = {'selected_ids': sorted(set(picks)), 'free_text': ''}
                elif isinstance(value, dict):
                    picks = value.get('selected') or value.get('selected_ids') or []
                    if not isinstance(picks, list):
                        picks = [picks] if picks else []
                    picks = [str(x).strip().upper() for x in picks if str(x).strip()]
                    free_text = str(value.get('text') or value.get('response') or '').strip()
                    answer_map[qid] = {'selected_ids': sorted(set(picks)), 'free_text': free_text}
                else:
                    text_value = str(value).strip()
                    picks = [text_value.upper()] if text_value else []
                    answer_map[qid] = {'selected_ids': sorted(set(picks)), 'free_text': text_value}
        elif isinstance(answers, list):
            for item in answers:
                if not isinstance(item, dict):
                    continue
                qid = str(item.get('question_id') or item.get('id') or '').strip()
                picked = item.get('selected')
                if isinstance(picked, list):
                    picks = [str(x).strip().upper() for x in picked if str(x).strip()]
                else:
                    picks = [str(picked).strip().upper()] if str(picked).strip() else []
                free_text = str(item.get('text') or item.get('response') or '').strip()
                if qid:
                    answer_map[qid] = {'selected_ids': sorted(set(picks)), 'free_text': free_text}

        questions = exam.get('questions') or []
        max_score = int(exam.get('max_score') or 300)
        per_question = 10

        score = 0
        correct_count = 0
        mistakes = []
        ai_review_questions = []

        for q in questions:
            qid = q.get('id')
            expected = sorted(set([str(x).strip().upper() for x in (q.get('correct_option_ids') or [])]))
            user_answer = answer_map.get(qid, {'selected_ids': [], 'free_text': ''})
            selected = sorted(set(user_answer.get('selected_ids') or []))
            free_text = str(user_answer.get('free_text') or '').strip()
            q_type = str(q.get('type') or 'single_choice').lower()

            is_free_text = q_type in {'simulation_sms', 'simulation_email', 'incident_response'}
            is_correct = False
            earned_points = 0

            if is_free_text:
                # Không tự động chấm, gom lại cho AI chấm sau
                ai_review_questions.append({
                    'question_id': qid,
                    'question': q.get('question', ''),
                    'category': q.get('category', ''),
                    'difficulty': q.get('difficulty_label') or q.get('difficulty', ''),
                    'type': q_type,
                    'free_text': free_text,
                    'simulation': q.get('simulation', {}),
                    'explanation': q.get('explanation', ''),
                })
                # Không cộng điểm, không tính đúng/sai
                continue

            # Chấm tự động các câu chọn đáp án
            is_correct = selected == expected
            earned_points = per_question if is_correct else 0

            if is_correct:
                score += earned_points
                correct_count += 1
            else:
                score += earned_points
                mistakes.append({
                    'question_id': qid,
                    'question': q.get('question', ''),
                    'category': q.get('category', ''),
                    'difficulty': q.get('difficulty_label') or q.get('difficulty', ''),
                    'type': q_type,
                    'expected': expected,
                    'selected': selected,
                    'free_text': free_text,
                    'earned_points': earned_points,
                    'explanation': q.get('explanation', ''),
                    'options': q.get('options') or [],
                })

        score = min(max_score, score)
        level_info = ScamIQAttempt.calculate_level(score)

        breakdown = {
            'easy': {'total': 0, 'correct': 0},
            'medium': {'total': 0, 'correct': 0},
            'hard': {'total': 0, 'correct': 0},
            'extreme': {'total': 0, 'correct': 0},
        }
        for q in questions:
            diff = str(q.get('difficulty') or 'medium').lower()
            if diff not in breakdown:
                diff = 'medium'
            breakdown[diff]['total'] += 1
            qid = q.get('id')
            expected = sorted(set([str(x).strip().upper() for x in (q.get('correct_option_ids') or [])]))
            user_answer = answer_map.get(qid, {'selected_ids': [], 'free_text': ''})
            selected = sorted(set(user_answer.get('selected_ids') or []))
            free_text = str(user_answer.get('free_text') or '').strip().lower()
            q_type = str(q.get('type') or 'single_choice').lower()

            is_correct = False
            if q_type in {'simulation_sms', 'simulation_email', 'incident_response'}:
                sim = q.get('simulation') or {}
                expected_keywords = [str(x).strip().lower() for x in (sim.get('expected_keywords') or []) if str(x).strip()]
                if expected_keywords:
                    hits = sum(1 for kw in expected_keywords if kw in free_text)
                    is_correct = (hits / max(len(expected_keywords), 1)) >= 0.6
                else:
                    is_correct = bool(free_text)
            else:
                is_correct = selected == expected

            if is_correct:
                breakdown[diff]['correct'] += 1

        response_payload = {
            'score': score,
            'max_score': max_score,
            'correct_count': correct_count,
            'wrong_count': max(0, len([q for q in questions if str(q.get('type') or '').lower() not in {'simulation_sms','simulation_email','incident_response'}]) - correct_count),
            'exam_title': exam.get('exam_title'),
            'level': level_info['current'],
            'level_bands': level_info['bands'],
            'mistakes': mistakes,
            'difficulty_breakdown': breakdown,
            'ai_review_questions': ai_review_questions,
            'is_ai_scored': not bool(ai_review_questions),
        }

        try:
            attempt = ScamIQAttempt.objects.create(
                user=request.user,
                exam_title=str(exam.get('exam_title') or 'Scam IQ Exam')[:255],
                score=score,
                max_score=max_score,
                correct_count=correct_count,
                wrong_count=response_payload['wrong_count'],
                level_code=str(level_info['current'].get('code') or '')[:40],
                level_label=str(level_info['current'].get('label') or '')[:120],
                difficulty_breakdown=breakdown,
                mistakes=mistakes[:30],
                ai_feedback=ai_review_questions, # Save raw questions initially
                is_ai_scored=not bool(ai_review_questions),
            )
            response_payload['attempt_id'] = attempt.id
            
            if ai_review_questions:
                task = score_scamiq_responses_task.delay(attempt.id)
                response_payload['ai_task_id'] = task.id
        except Exception:
            logger.exception('Failed to persist Scam IQ attempt for user_id=%s', request.user.id)

        return Response(response_payload)


class ScamIQHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        limit = request.query_params.get('limit', '15')
        try:
            limit_n = max(1, min(50, int(limit)))
        except ValueError:
            limit_n = 15

        attempts = (
            ScamIQAttempt.objects
            .filter(user=request.user)
            .order_by('-created_at')[:limit_n]
        )

        data = [
            {
                'id': a.id,
                'exam_title': a.exam_title,
                'score': a.score,
                'max_score': a.max_score,
                'correct_count': a.correct_count,
                'wrong_count': a.wrong_count,
                'level_code': a.level_code,
                'level_label': a.level_label,
                'difficulty_breakdown': a.difficulty_breakdown,
                'created_at': a.created_at.isoformat(),
            }
            for a in attempts
        ]

        return Response({
            'count': len(data),
            'results': data,
        })
