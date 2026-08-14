import re

with open("api/core/tasks.py", "r", encoding="utf-8") as f:
    content = f.read()

# Replace docstring
content = content.replace("Generates: article content (HTML), 5 quizzes.", "Generates: article content (HTML).")

# Find STAGE 3 and STAGE 4
stage3_idx = content.find("# ──── STAGE 3: Generate 5 quizzes ────")
stage4_idx = content.find("# ──── STAGE 4: Finalize ────")

if stage3_idx != -1 and stage4_idx != -1:
    content = content[:stage3_idx] + content[stage4_idx:]

# Also remove quiz from STAGE 4 and pushes
content = content.replace("'quizzes': quizzes,", "")
content = content.replace("| {len(quizzes)} quizzes", "")
content = content.replace("({len(quizzes)} quiz).", ".")

with open("api/core/tasks.py", "w", encoding="utf-8") as f:
    f.write(content)
