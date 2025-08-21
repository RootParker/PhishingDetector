from django.shortcuts import render
from .utils import analyze_email


def analyze_view(request):
    if request.method == "POST":
        raw_text = request.POST.get("raw_text", "")
        eml_file = request.FILES.get("eml_file")
        eml_bytes = eml_file.read() if eml_file else None

        result = analyze_email(raw_text, eml_bytes)
        return render(request, "analyzer/result.html", {"result": result})

    return render(request, "analyzer/upload.html")
