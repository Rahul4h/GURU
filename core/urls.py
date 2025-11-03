# app/urls.py (update)
from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('analyze/', views.analyze_handle, name='analyze_handle'),
    path('suggestions/', views.suggestions_page, name='suggestions'),
    path('api/suggest/', views.ml_suggestions_view, name='get_ml_suggestions'),
    

    path('signup/', views.signup_view, name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('verify/<uidb64>/<token>/', views.verify_email, name='verify_email'),
    


    path('profile/', views.profile, name='profile'),
    # new endpoints:
    path('profile/update-picture/', views.update_profile_picture, name='update_profile'),
    path('profile/add-post/', views.add_post, name='add_post'),
    path('profile/add-tutorial/', views.add_tutorial, name='add_tutorial'),
    path('profile/take-snapshot/', views.take_snapshot, name='take_snapshot'),
    
    path('blog/', views.blog_page, name='blog_page'),
    path("blog/<int:post_id>/", views.blog_detail, name="blog_detail"),
    path('conprep/',views.conprep_page, name='conprep_page'),
    path('contact/', views.contact_page, name='contact'),

 # new blog page


]
