from django import forms
from .models import LearnLesson, Article

class LearnLessonForm(forms.ModelForm):
    class Meta:
        model = LearnLesson
        fields = ['title', 'slug', 'content', 'category', 'cover_image', 'is_published']
        widgets = {
            'title': forms.TextInput(attrs={'placeholder': 'Nhập tiêu đề bài học...'}),
            'slug': forms.TextInput(attrs={'placeholder': 'duong-dan-bai-hoc (để trống để tự tạo)'}),
            'content': forms.Textarea(attrs={'id': 'editor', 'placeholder': 'Nội dung bài học...'}),
        }

class ArticleForm(forms.ModelForm):
    class Meta:
        model = Article
        fields = ['title', 'slug', 'content', 'category', 'cover_image', 'is_published']
        widgets = {
            'title': forms.TextInput(attrs={'placeholder': 'Nhập tiêu đề bài viết...'}),
            'slug': forms.TextInput(attrs={'placeholder': 'duong-dan-bai-viet (để trống để tự tạo)'}),
            'content': forms.Textarea(attrs={'id': 'editor', 'placeholder': 'Nội dung bài viết...'}),
        }

from .models import LearnScenario
class LearnScenarioForm(forms.ModelForm):
    class Meta:
        model = LearnScenario
        fields = ['title', 'description', 'content']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'admin-form-input', 'placeholder': 'Tiêu đề kịch bản...'}),
            'description': forms.Textarea(attrs={'class': 'admin-form-input', 'rows': 3, 'placeholder': 'Mô tả ngắn về kịch bản...'}),
            'content': forms.Textarea(attrs={'class': 'admin-form-input', 'rows': 10, 'placeholder': 'JSON content for scenario flow...'}),
        }
