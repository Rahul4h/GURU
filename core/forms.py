# app/forms.py
from django import forms
from .models import Profile, Post, Tutorial

class ProfilePictureForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['profile_picture', 'bio']

class PostForm(forms.ModelForm):
    class Meta:
        model = Post
        fields = ['title', 'content', 'image']

class TutorialForm(forms.ModelForm):
    class Meta:
        model = Tutorial
        fields = ['title', 'content', 'video']
