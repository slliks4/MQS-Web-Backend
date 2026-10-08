from django.urls import path

from .views import DiscordLoginView

urlpatterns = [
    path(
        "discord/register/",
        DiscordLoginView.as_view(),
        name="discord-register",
    ),
]
