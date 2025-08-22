from django.db import models

class EmailSample(models.Model):
    subject = models.CharField(max_length=255)
    sender = models.CharField(max_length=255)
    body = models.TextField()
    is_phishing = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
