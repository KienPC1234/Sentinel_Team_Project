from django import forms
from .models import LearnLesson, Article

class LearnLessonForm(forms.ModelForm):
    class Meta:
        model = LearnLesson
        fields = ['title', 'slug', 'summary', 'content', 'category', 'cover_image', 'is_published']
        widgets = {
            'title': forms.TextInput(attrs={'placeholder': 'Nhập tiêu đề bài học...'}),
            'slug': forms.TextInput(attrs={'placeholder': 'duong-dan-bai-hoc (để trống để tự tạo)'}),
            'summary': forms.Textarea(attrs={'placeholder': 'Tóm tắt ngắn (1-3 câu)...', 'rows': 3}),
            'content': forms.Textarea(attrs={'id': 'editor', 'placeholder': 'Nội dung bài học...'}),
            'category': forms.Select(attrs={'class': 'liquid-select'}),
            'cover_image': forms.ClearableFileInput(attrs={'class': 'sr-only', 'accept': 'image/*'}),
            'is_published': forms.CheckboxInput(attrs={'class': 'sr-only'}),
        }

class ArticleForm(forms.ModelForm):
    class Meta:
        model = Article
        fields = ['title', 'slug', 'summary', 'content', 'category', 'cover_image', 'is_published']
        widgets = {
            'title': forms.TextInput(attrs={'placeholder': 'Nhập tiêu đề bài viết...'}),
            'slug': forms.TextInput(attrs={'placeholder': 'duong-dan-bai-viet (để trống để tự tạo)'}),
            'summary': forms.Textarea(attrs={'placeholder': 'Tóm tắt ngắn (1-3 câu)...', 'rows': 3}),
            'content': forms.Textarea(attrs={'id': 'editor', 'placeholder': 'Nội dung bài viết...'}),
            'category': forms.Select(attrs={'class': 'liquid-select'}),
            'cover_image': forms.ClearableFileInput(attrs={'class': 'sr-only', 'accept': 'image/*'}),
            'is_published': forms.CheckboxInput(attrs={'class': 'sr-only'}),
        }

from .models import LearnScenario
class LearnScenarioForm(forms.ModelForm):
    class Meta:
        model = LearnScenario
        fields = ['title', 'article', 'description', 'content']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'admin-form-input', 'placeholder': 'Tiêu đề kịch bản...'}),
            'article': forms.Select(attrs={'class': 'admin-form-input'}),
            'description': forms.Textarea(attrs={'class': 'admin-form-input', 'rows': 3, 'placeholder': 'Mô tả ngắn về kịch bản...'}),
            'content': forms.Textarea(attrs={'id': 'editor', 'placeholder': 'JSON content for scenario flow...'}),
        }
