from django import forms
from martor.fields import MartorFormField
from .models import LearnLesson, Article

class LearnLessonForm(forms.ModelForm):
    content = MartorFormField()
    
    class Meta:
        model = LearnLesson
        fields = ['title', 'slug', 'content', 'category', 'cover_image', 'is_published']

class ArticleForm(forms.ModelForm):
    content = MartorFormField()
    
    class Meta:
        model = Article
        fields = ['title', 'slug', 'content', 'category', 'cover_image', 'is_published']
