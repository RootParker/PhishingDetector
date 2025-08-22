from django.contrib import admin
from .models import EmailSample

@admin.register(EmailSample)
class EmailSampleAdmin(admin.ModelAdmin):
    list_display = ('subject', 'sender', 'is_phishing', 'created_at')
    list_filter = ('is_phishing', 'created_at')
    search_fields = ('subject', 'sender')
