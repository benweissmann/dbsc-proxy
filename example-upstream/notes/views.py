from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login
from .models import Note


def index(request):
    """Homepage - shows login/registration options or redirects to dashboard"""
    if request.user.is_authenticated:
        return redirect("dashboard")
    return render(request, "notes/index.html")


def register(request):
    """Registration view"""
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect("dashboard")
    else:
        form = UserCreationForm()
    return render(request, "registration/register.html", {"form": form})


@login_required
def dashboard(request):
    """Dashboard view for logged-in users to manage their note"""
    # Get or create the note for the current user
    note, created = Note.objects.get_or_create(
        user=request.user, defaults={"note_text": ""}
    )

    if request.method == "POST":
        note_text = request.POST.get("note_text", "")
        note.note_text = note_text
        note.save()
        return redirect("dashboard")

    return render(request, "notes/dashboard.html", {"note": note})
