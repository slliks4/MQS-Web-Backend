# apps/authorization/services/discord_registration.py

import secrets
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import IntegrityError, transaction

from apps.authorization.services.discord import (
    DiscordAPIError,
    DiscordClient,
)


class DiscordRegistrationError(Exception):
    pass


class DiscordRegistrationSessionError(Exception):
    pass


class DiscordRegistrationConflictError(Exception):
    pass


def start_discord_registration(
    *,
    code: str,
    redirect_uri: str,
) -> dict[str, Any]:
    discord = DiscordClient()

    token_data = discord.exchange_code(
        code=code,
        redirect_uri=redirect_uri,
    )

    access_token = token_data.get("access_token")

    if not isinstance(access_token, str):
        raise DiscordAPIError(
            {
                "message": "Discord did not return an access token.",
            }
        )

    discord_user = discord.get_current_user(
        access_token=access_token,
    )

    discord_user_id = discord_user.get("id")
    email = discord_user.get("email")
    username = discord_user.get("username")

    if not isinstance(discord_user_id, str):
        raise DiscordRegistrationError(
            "Discord did not return a user ID.",
        )

    if not isinstance(username, str):
        raise DiscordRegistrationError(
            "Discord did not return a username.",
        )

    if not isinstance(email, str) or not email.strip():
        raise DiscordRegistrationError(
            "Discord did not provide an email address.",
        )

    guild_member = discord.get_guild_member(
        discord_user_id=discord_user_id,
    )

    display_name = (
        guild_member.get("nick")
        or discord_user.get("global_name")
        or username
    )

    avatar_url = build_discord_avatar_url(
        discord_user=discord_user,
    )

    # This value stays on the backend.
    role = resolve_application_role(
        guild_member=guild_member,
    )

    registration_code = secrets.token_urlsafe(32)
    timeout = get_registration_session_timeout()

    pending_registration = {
        "discord_id": discord_user_id,
        "username": username,
        "display_name": display_name,
        "email": email.strip().lower(),
        "email_verified": bool(
            discord_user.get("verified"),
        ),
        "avatar_url": avatar_url,
        "role": role,
    }

    cache.set(
        make_registration_cache_key(
            registration_code,
        ),
        pending_registration,
        timeout=timeout,
    )

    return {
        "registration_code": registration_code,
        "expires_in": timeout,
    }


def get_public_registration_session(
    *,
    registration_code: str,
) -> dict[str, Any]:
    pending_registration = get_pending_registration(
        registration_code=registration_code,
    )

    # Never return role, Discord role IDs or access tokens.
    return {
        "username": pending_registration["username"],
        "display_name": pending_registration["display_name"],
        "email": pending_registration["email"],
        "avatar_url": pending_registration["avatar_url"],
    }


def complete_discord_registration(
    *,
    registration_code: str,
    full_name: str,
    password: str,
) -> dict[str, Any]:
    pending_registration = get_pending_registration(
        registration_code=registration_code,
    )

    User = get_user_model()

    email = pending_registration["email"]
    discord_id = pending_registration["discord_id"]

    if User._default_manager.filter(
        email__iexact=email,
    ).exists():
        raise DiscordRegistrationConflictError(
            "An account already exists with this email.",
        )

    user_field_names = {
        field.name
        for field in User._meta.get_fields()
    }

    if (
        "discord_id" in user_field_names
        and User._default_manager.filter(
            discord_id=discord_id,
        ).exists()
    ):
        raise DiscordRegistrationConflictError(
            "This Discord account is already registered.",
        )

    try:
        with transaction.atomic():
            user = create_user_from_discord_registration(
                pending_registration=pending_registration,
                full_name=full_name,
                password=password,
            )
    except IntegrityError as error:
        raise DiscordRegistrationConflictError(
            "An account already exists for this Discord user.",
        ) from error

    # Consume the code only after the user is created successfully.
    cache.delete(
        make_registration_cache_key(
            registration_code,
        )
    )

    return {
        "id": str(user.pk),
        "email": user.email,
        "full_name": full_name,
    }


def create_user_from_discord_registration(
    *,
    pending_registration: dict[str, Any],
    full_name: str,
    password: str,
):
    """
    This is the only function that may need adjustment
    to match the fields on your custom User model.
    """

    User = get_user_model()

    return User._default_manager.create_user(
        email=pending_registration["email"],
        password=password,
        full_name=full_name,

        # These are all server-controlled.
        role=pending_registration["role"],
        discord_id=pending_registration["discord_id"],
        discord_username=pending_registration["username"],
        discord_avatar_url=pending_registration["avatar_url"],
    )


def get_pending_registration(
    *,
    registration_code: str,
) -> dict[str, Any]:
    pending_registration = cache.get(
        make_registration_cache_key(
            registration_code,
        )
    )

    if not isinstance(pending_registration, dict):
        raise DiscordRegistrationSessionError(
            "The registration session has expired or is invalid.",
        )

    return pending_registration


def resolve_application_role(
    *,
    guild_member: dict[str, Any],
) -> str:
    member_role_ids = set(
        guild_member.get("roles") or [],
    )

    # Highest-priority roles should come first in settings.
    for mapping in settings.DISCORD.get(
        "ROLE_MAP",
        [],
    ):
        discord_role_id = mapping.get(
            "discord_role_id",
        )
        application_role = mapping.get(
            "application_role",
        )

        if (
            discord_role_id
            and application_role
            and discord_role_id in member_role_ids
        ):
            return application_role

    return settings.DISCORD.get(
        "DEFAULT_APPLICATION_ROLE",
        "member",
    )


def build_discord_avatar_url(
    *,
    discord_user: dict[str, Any],
) -> str | None:
    discord_user_id = discord_user.get("id")
    avatar_hash = discord_user.get("avatar")

    if not discord_user_id or not avatar_hash:
        return None

    extension = (
        "gif"
        if str(avatar_hash).startswith("a_")
        else "png"
    )

    return (
        "https://cdn.discordapp.com/avatars/"
        f"{discord_user_id}/{avatar_hash}.{extension}"
    )


def get_registration_session_timeout() -> int:
    return int(
        settings.DISCORD.get(
            "REGISTER_SESSION_TIMEOUT",
            15 * 60,
        )
    )


def make_registration_cache_key(
    registration_code: str,
) -> str:
    return (
        "authorization:"
        "discord-registration:"
        f"{registration_code}"
    )
