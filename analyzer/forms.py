from django import forms
from .models import EmailSample

class EmailAnalyzeForm(forms.ModelForm):
    class Meta:
        model = EmailSample
        fields = ['sender', 'subject', 'content']
        widgets = {
            'sender': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Sender Email'}),
            'subject': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Subject'}),
            'content': forms.Textarea(attrs={'class': 'form-control', 'rows': 5, 'placeholder': 'Email content'}),
        }
