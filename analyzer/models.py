from django.db import models
from django.utils import timezone
from django.core.validators import FileExtensionValidator


class EmailSample(models.Model):
    source_label = models.CharField(max_length=120, blank=True, help_text="Optional note for where this email came from")
    raw_text = models.TextField(blank=True)
    eml_file = models.FileField(upload_to='uploads/', blank=True, null=True,
                                validators=[FileExtensionValidator(['eml'])])


    from_addr = models.CharField(max_length=320, blank=True)
    subject = models.CharField(max_length=998, blank=True)
    received_at = models.DateTimeField(blank=True, null=True)


    verdict = models.CharField(max_length=32, default='unknown')
    score = models.FloatField(default=0.0)
    explanations = models.JSONField(default=list, blank=True)
    indicators = models.JSONField(default=dict, blank=True)


    created_at = models.DateTimeField(default=timezone.now)


    def __str__(self):
        return f"EmailSample #{self.pk} — {self.subject[:50]}"