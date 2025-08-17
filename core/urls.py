# app/urls.py (update)
from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('analyze/', views.analyze_handle, name='analyze_handle'),
    path('suggestions/', views.suggestions_page, name='suggestions'),
    path('api/suggest/', views.ml_suggestions_view, name='get_ml_suggestions'),
    path('login', views.handlelogin, name='handlelogin'),
    path('logout', views.handlelogout, name='handlelogout'),
    path('signup', views.handlesignup, name='handlesignup'),
    path('profile/', views.profile, name='profile'),
    # new endpoints:
    path('profile/update-picture/', views.update_profile_picture, name='update_profile'),
    path('profile/add-post/', views.add_post, name='add_post'),
    path('profile/add-tutorial/', views.add_tutorial, name='add_tutorial'),
    path('profile/take-snapshot/', views.take_snapshot, name='take_snapshot'),
    path('activate/<uidb64>/<token>/', views.activate_account, name='activate'),
    path('blog/', views.blog_page, name='blog_page'),
    path("blog/<int:post_id>/", views.blog_detail, name="blog_detail"),
    

 # new blog page


]
