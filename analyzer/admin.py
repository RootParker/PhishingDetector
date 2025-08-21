from django.contrib import admin
from .models import EmailSample


@admin.register(EmailSample)
class EmailSampleAdmin(admin.ModelAdmin):
    list_display = ("id", "subject", "from_addr", "verdict", "score", "created_at")
    list_filter = ("verdict", "created_at")
    search_fields = ("subject", "from_addr", "raw_text")