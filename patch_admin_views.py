import re

with open("PKV/views/admin_views.py", "r", encoding="utf-8") as f:
    content = f.read()

# Replace magic_save_article_api logic
old_save = """def magic_save_article_api(request):
    \"\"\"API to save the AI-generated article and quizzes\"\"\"
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Only POST allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        
        with transaction.atomic():
            article = Article.objects.create(
                title=data.get('title'),
                content=data.get('content'),
                category=data.get('category', 'news'),
                is_published=False
            )
            
            quizzes_data = data.get('quizzes', [])
            for quiz_data in quizzes_data:
                if quiz_data and quiz_data.get('question'):
                    LearnQuiz.objects.create(
                        article=article,
                        question=quiz_data.get('question'),
                        question_type=quiz_data.get('question_type', 'single_choice'),
                        options=quiz_data.get('options', []),
                        correct_answer=quiz_data.get('correct_answer'),
                        correct_answers=quiz_data.get('correct_answers', []),
                        explanation=quiz_data.get('explanation', '')
                    )
                
        return JsonResponse({'status': 'success', 'article_id': article.id})"""

new_save = """def magic_save_article_api(request):
    \"\"\"API to save the AI-generated article\"\"\"
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Only POST allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        
        article = Article.objects.create(
            title=data.get('title'),
            content=data.get('content'),
            category=data.get('category', 'news'),
            is_published=False
        )
                
        return JsonResponse({'status': 'success', 'article_id': article.id})"""

content = content.replace(old_save, new_save)

with open("PKV/views/admin_views.py", "w", encoding="utf-8") as f:
    f.write(content)
