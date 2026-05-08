from django.contrib import admin
from django.urls import path

from rendezvous import views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("auth/signup", views.signup_view),
    path("auth/login", views.login_view),
    path("auth/verify/<str:token>", views.verify_view),
    path("register", views.register_view),
    path("peers", views.peers_view),
]
