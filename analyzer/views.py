from django.shortcuts import render
from .models import EmailSample

def home(request):
    total_emails = EmailSample.objects.count()
    phishing_emails = EmailSample.objects.filter(is_phishing=True).count()
    legitimate_emails = EmailSample.objects.filter(is_phishing=False).count()

    context = {
        'total_emails': total_emails,
        'phishing_emails': phishing_emails,
        'legitimate_emails': legitimate_emails,
    }
    return render(request, 'analyzer/home.html', context)
