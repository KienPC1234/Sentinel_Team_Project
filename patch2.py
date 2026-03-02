with open("PKV/templates/Admin/magic_create_article.html", "r", encoding="utf-8") as f:
    lines = f.readlines()

new_lines = []
for i, line in enumerate(lines):
    if "5 câu Quiz" in line or "text-purple-500/50" in line:
        pass
    elif ">Quiz<" in line:
        pass
    elif "{ name: 'Quiz'," in line:
        pass
    else:
        new_lines.append(line)

with open("PKV/templates/Admin/magic_create_article.html", "w", encoding="utf-8") as f:
    f.writelines(new_lines)
