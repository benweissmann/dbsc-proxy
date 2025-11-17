from django.db import models


class Note(models.Model):
    user = models.OneToOneField("auth.User", on_delete=models.CASCADE, primary_key=True)
    note_text = models.CharField(max_length=200)
    created_at = models.DateTimeField("date created", auto_now_add=True)
    updated_at = models.DateTimeField("date updated", auto_now=True)
