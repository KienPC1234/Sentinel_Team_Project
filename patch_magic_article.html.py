import re

with open("PKV/templates/Admin/magic_create_article.html", "r", encoding="utf-8") as f:
    content = f.read()

# Remove Quiz block (card)
quiz_card_pattern = r'<!-- Quizzes -->[\s\S]*?</div>\s*</div>\s*<!-- Summary stats -->'
content = re.sub(quiz_card_pattern, '<!-- Summary stats -->', content)

# Remove Quiz stats
quiz_stats_pattern = r'<div class="text-center p-3 rounded-xl bg-purple-500/5 border border-purple-500/10">[\s\S]*?</div>'
content = re.sub(quiz_stats_pattern, '', content)

# Change grid-cols-2 to grid-cols-1
content = content.replace('<div class="grid grid-cols-2 gap-3">', '<div class="grid grid-cols-1 gap-3">')

# Remove "· 5 quiz" from text
content = content.replace('AI tạo bài viết tin tức · 5 quiz', 'AI tạo bài viết tin tức')
content = content.replace('gồm nội dung chi tiết và 5 câu quiz.', 'gồm nội dung chi tiết.')

# Remove JS
content = content.replace('quizzes: [],', '')
content = content.replace('this.quizzes = [];', '')

# Remove quiz JS listeners
quiz_js_pattern1 = r'if \(msg\.data\.quiz_item !== undefined\) \{[\s\S]*?\}'
content = re.sub(quiz_js_pattern1, '', content)

content = content.replace('if (msg.data.quizzes) this.quizzes = msg.data.quizzes;', '')
content = content.replace('this.quizzes = msg.data.quizzes || [];', '')
content = content.replace("this._log('Done! quizzes=' + this.quizzes.length);", "this._log('Done!');")
content = content.replace('quizzes: this.quizzes,', '')

with open("PKV/templates/Admin/magic_create_article.html", "w", encoding="utf-8") as f:
    f.write(content)
