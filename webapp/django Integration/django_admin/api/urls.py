from django.contrib import admin
from django.urls import path
from .views import URLPredictionApiView

urlpatterns = [
    path('predict/', URLPredictionApiView.as_view()),
]
