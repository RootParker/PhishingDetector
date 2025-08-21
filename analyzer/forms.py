from django import forms
from .models import EmailSample


class EmailUploadForm(forms.ModelForm):
    class Meta:
        model = EmailSample
        fields = ["source_label", "raw_text", "eml_file"]
        widgets = {
            "source_label": forms.TextInput(attrs={"class": "form-control", "placeholder": "e.g. Gmail forward, Helpdesk ticket #123"}),
            "raw_text": forms.Textarea(attrs={"class": "form-control", "rows": 10, "placeholder": "Paste raw email (including headers) or upload a .eml file below"}),
}


def clean(self):
    cleaned = super(EmailUploadForm, self).clean()
    if not cleaned.get("raw_text") and not cleaned.get("eml_file"):
        raise forms.ValidationError("Provide raw text or upload a .eml file.")
    return cleaned
