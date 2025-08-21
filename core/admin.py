from django.contrib import admin
from .models import Profile, Post, Tutorial,WeaknessSnapshot,Comment,Reaction,CommentReaction

admin.site.register(Profile)
admin.site.register(Post)
admin.site.register(Tutorial)
admin.site.register(WeaknessSnapshot)
admin.site.register(Comment)
admin.site.register(Reaction)
admin.site.register(CommentReaction)

