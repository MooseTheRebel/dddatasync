import os

SECRET_KEY = os.environ.get("SECRET_KEY", "insecure-dev-key-do-not-use-in-production")
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "rendezvous.apps.RendezvousConfig",
]

ROOT_URLCONF = "rendezvous.urls"
WSGI_APPLICATION = "rendezvous.wsgi.application"

# In-memory SQLite satisfies Django's default-database requirement without
# creating any files.  The rendezvous server stores all state in the
# in-process registry dict (see registry.py) and never queries the ORM.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

TASKS = {
    "default": {
        "BACKEND": "django.tasks.backends.immediate.ImmediateBackend"
    }
}
