import os
import markdown
from django.shortcuts import render
from django.http import Http404, HttpResponse
from django.conf import settings
from django.utils.safestring import mark_safe

def helps_page_view(request, slug='index'):
    """
    Renders a Markdown file from the /helps directory.
    - slug: The filename (without .md extension). Defaults to 'index'.
    """
    helps_dir = os.path.join(settings.BASE_DIR, 'helps')
    
    # List all help articles for sidebar
    articles = []
    try:
        import re
        for filename in sorted(os.listdir(helps_dir)):
            if filename.endswith('.md'):
                f_slug = filename[:-3]
                f_path = os.path.join(helps_dir, filename)
                with open(f_path, 'r', encoding='utf-8') as f:
                    first_line = f.readline()
                    f_title = "Hướng dẫn"
                    h1_match = re.search(r'#\s+(.+)', first_line)
                    if h1_match:
                        f_title = h1_match.group(1).strip()
                    elif not first_line.startswith('#'):
                        # Check next few lines if first line is empty or doesn't have H1
                        content_peek = f.read(200)
                        h1_match = re.search(r'#\s+(.+)', content_peek)
                        if h1_match:
                            f_title = h1_match.group(1).strip()
                    
                    articles.append({
                        'slug': f_slug,
                        'title': f_title,
                        'active': f_slug == slug
                    })
    except Exception as e:
        pass

    file_path = os.path.join(helps_dir, f"{slug}.md")

    # Security check: ensure the file is within the helps directory
    if not os.path.abspath(file_path).startswith(os.path.abspath(helps_dir)):
        raise Http404("Đường dẫn không hợp lệ.")

    if not os.path.exists(file_path):
        if slug != 'index':
             file_path = os.path.join(helps_dir, "index.md")
             if not os.path.exists(file_path):
                 raise Http404("Trang hướng dẫn không tồn tại.")
             slug = 'index'
        else:
             raise Http404("Trang hướng dẫn không tồn tại.")

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            html_content = markdown.markdown(
                content,
                extensions=['extra', 'codehilite', 'toc', 'admonition', 'nl2br']
            )
            
            # Simple title extraction from first H1
            title = "Trung tâm hỗ trợ"
            import re
            h1_match = re.search(r'#\s+(.+)', content)
            if h1_match:
                title = h1_match.group(1).strip()

            return render(request, 'Helps/helps.html', {
                'content': mark_safe(html_content),
                'title': title,
                'slug': slug,
                'articles': articles
            })
    except Exception as e:
        return HttpResponse(f"Lỗi khi đọc file hướng dẫn: {str(e)}", status=500)
