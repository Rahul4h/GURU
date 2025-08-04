from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('analyze/', views.analyze_handle, name='analyze_handle'),
    path('suggestions/', views.suggestions_page, name='suggestions'),
    path('api/suggest/', views.ml_suggestions_view, name='get_ml_suggestions'),
    path ('login', views.handlelogin, name='handlelogin'),
    path ('logout', views.handlelogout, name='handlelogout'),
    path ('signup', views.handlesignup, name='handlesignup'),

]
