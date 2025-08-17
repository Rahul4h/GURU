# app/models.py
from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone
import json

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)
    bio = models.TextField(blank=True, default='')

    def __str__(self):
        return self.user.username



class Tutorial(models.Model):
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    content = models.TextField()
    video = models.FileField(upload_to='tutorial_videos/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} — {self.author.username}"

class WeaknessSnapshot(models.Model):
    """
    Snapshot of aggregated tag weakness for a user, taken at a point in time.
    `tag_scores` stores a JSON mapping tag->weakness_score (0..1).
    `avg_weakness` is a simple aggregate (mean of tag scores).
    `rating` is the average/last rating at snapshot time (optional).
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(default=timezone.now)
    tag_scores = models.JSONField(default=dict)  # { "implementation": 0.45, ... }
    avg_weakness = models.FloatField(default=0.0)
    rating = models.IntegerField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"WeaknessSnapshot {self.user.username} @ {self.created_at.isoformat()}"




class Post(models.Model):  # your existing one
    title = models.CharField(max_length=200)
    content = models.TextField()
    image = models.ImageField(upload_to='posts/', null=True, blank=True)

    author = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


class Comment(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="comments")
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    parent = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.CASCADE, related_name="replies"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Comment by {self.user.username} on {self.post.title}"


class Reaction(models.Model):
    REACTION_CHOICES = [
        ("like", "Like"),
        ("love", "Love"),
        ("dislike", "Dislike"),
    ]
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="reactions")
    user = models.ForeignKey(User, on_delete=models.CASCADE)
   
    reaction_type = models.CharField(max_length=20, choices=REACTION_CHOICES , default="like")

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("post", "user")  # one reaction per user per post

    def __str__(self):
        return f"{self.user.username} {self.reaction_type} {self.post.title}"





# core/models.py



