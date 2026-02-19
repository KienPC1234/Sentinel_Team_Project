from django.urls import path
from .views import AnalyzeImagesView, AnalyzeAudioView

urlpatterns = [
    path('analyze-images', AnalyzeImagesView.as_view(), name='analyze-images'),
    path('analyze-audio', AnalyzeAudioView.as_view(), name='analyze-audio'),
]
