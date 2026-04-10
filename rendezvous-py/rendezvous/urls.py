from django.urls import path

from rendezvous import views

urlpatterns = [
    path("register", views.register_view),
    path("peers", views.peers_view),
]
