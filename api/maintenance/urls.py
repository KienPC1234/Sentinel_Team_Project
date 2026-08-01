from django.urls import path
from .views import ReportCrashView

urlpatterns = [
    path('report-crash', ReportCrashView.as_view(), name='report-crash'),
]
