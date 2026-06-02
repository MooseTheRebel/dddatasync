import json
import logging
import os
import secrets

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core.mail import send_mail
from django.http import HttpRequest, JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from rendezvous import registry
from rendezvous.models import AccountStatus, SessionToken, UserAccount

logger = logging.getLogger(__name__)

# Pre-computed hash used when a login username is not found, so that
# check_password always runs its full PBKDF2 iteration and prevents
# username enumeration via response-time differences.
_DUMMY_HASH = make_password("_dummy_")


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _authenticate(request: HttpRequest) -> "UserAccount | None":
    """Return the UserAccount for a valid Bearer token, or None."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token_str = auth[len("Bearer "):]
    now = timezone.now()
    try:
        record = (
            SessionToken.objects.select_related("user")
            .filter(token=token_str, expires_at__gt=now, user__status=AccountStatus.APPROVED)
            .first()
        )
        return record.user if record else None
    except Exception:
        return None


def _create_session_token(user: "UserAccount") -> str:
    """Create and persist a new session token for *user*, return the token string."""
    from datetime import timedelta
    token_str = secrets.token_hex(32)
    expires = timezone.now() + timedelta(seconds=settings.SESSION_TOKEN_TTL_SECS)
    SessionToken.objects.create(user=user, token=token_str, expires_at=expires)
    return token_str


# ---------------------------------------------------------------------------
# Auth views
# ---------------------------------------------------------------------------

@csrf_exempt
def signup_view(request: HttpRequest) -> JsonResponse:
    """POST /auth/signup — create a new pending account and send a verification email."""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)

    try:
        data = json.loads(request.body)
        username = data["username"].strip()
        email = data["email"].strip().lower()
        password = data["password"]
    except (KeyError, json.JSONDecodeError, AttributeError):
        return JsonResponse({"error": "username, email, and password are required"}, status=400)

    if not username or not email or not password:
        return JsonResponse({"error": "username, email, and password must be non-empty"}, status=400)

    if UserAccount.objects.filter(username=username).exists():
        return JsonResponse({"error": "username already taken"}, status=409)
    if UserAccount.objects.filter(email=email).exists():
        return JsonResponse({"error": "email already registered"}, status=409)

    auto_approve = os.environ.get("AUTO_APPROVE_USERS", "").lower() in ("true", "1")
    if auto_approve:
        status = AccountStatus.APPROVED
        verification_token = ""
    else:
        status = AccountStatus.PENDING
        verification_token = secrets.token_hex(32)

    account = UserAccount.objects.create(
        username=username,
        email=email,
        password_hash=make_password(password),
        status=status,
        verification_token=verification_token,
    )

    if not auto_approve:
        verify_url = f"{settings.BASE_URL}/auth/verify/{verification_token}"
        try:
            send_mail(
                subject="Verify your dddatasync account",
                message=(
                    f"Hi {username},\n\n"
                    f"Please verify your email address by visiting:\n\n"
                    f"  {verify_url}\n\n"
                    f"If you did not create this account, you can ignore this email.\n"
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )
        except Exception as exc:
            logger.error("failed to send verification email to %s: %s", email, exc)

    logger.info("signup username=%s email=%s auto_approve=%s", username, email, auto_approve)
    return JsonResponse(
        {"message": "Account created. Please check your email to verify your address."},
        status=201,
    )


@csrf_exempt
def verify_view(request: HttpRequest, token: str) -> JsonResponse:
    """GET /auth/verify/<token> — verify email and approve the account."""
    try:
        account = UserAccount.objects.get(verification_token=token, status=AccountStatus.PENDING)
    except UserAccount.DoesNotExist:
        return JsonResponse({"error": "invalid or expired verification token"}, status=404)

    account.status = AccountStatus.APPROVED
    account.verification_token = ""
    account.save(update_fields=["status", "verification_token"])

    logger.info("verified username=%s", account.username)
    return JsonResponse({"message": "Email verified. You can now log in."})


@csrf_exempt
def login_view(request: HttpRequest) -> JsonResponse:
    """POST /auth/login — authenticate and return a session token."""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)

    try:
        data = json.loads(request.body)
        username = data["username"]
        password = data["password"]
    except (KeyError, json.JSONDecodeError):
        return JsonResponse({"error": "username and password are required"}, status=400)

    try:
        account = UserAccount.objects.get(username=username)
        password_hash = account.password_hash
        account_status = account.status
    except UserAccount.DoesNotExist:
        # Use the dummy hash so check_password always runs its full PBKDF2
        # iteration, preventing username enumeration via timing differences.
        password_hash = _DUMMY_HASH
        account_status = None

    password_ok = check_password(password, password_hash)

    if not password_ok or account_status is None:
        return JsonResponse({"error": "invalid credentials"}, status=401)

    if account_status == AccountStatus.PENDING:
        return JsonResponse(
            {"error": "account pending email verification — check your inbox"}, status=403
        )
    if account_status == AccountStatus.BLOCKED:
        return JsonResponse({"error": "account blocked"}, status=403)

    token_str = _create_session_token(account)  # account exists: account_status is not None
    logger.info("login username=%s", username)
    return JsonResponse({"token": token_str})


# ---------------------------------------------------------------------------
# Peer registry views (require Bearer token auth for mutations)
# ---------------------------------------------------------------------------

@csrf_exempt
def register_view(request: HttpRequest) -> JsonResponse:
    """POST /register — upsert a peer.  DELETE /register — remove a peer."""
    if request.method == "POST":
        user = _authenticate(request)
        if user is None:
            return JsonResponse({"error": "unauthorized"}, status=401)
        data = json.loads(request.body)
        if data.get("username") != user.username:
            return JsonResponse({"error": "forbidden"}, status=403)
        registry.upsert(
            data["username"],
            data["node_id"],
            data["addrs"],
            data.get("relay_url"),
        )
        logger.info("registered username=%s node_id=%s", data["username"], data["node_id"])
        return JsonResponse({})

    if request.method == "DELETE":
        user = _authenticate(request)
        if user is None:
            return JsonResponse({"error": "unauthorized"}, status=401)
        data = json.loads(request.body)
        if data.get("username") != user.username:
            return JsonResponse({"error": "forbidden"}, status=403)
        registry.remove(data["username"], data["node_id"])
        logger.info("deregistered username=%s node_id=%s", data["username"], data["node_id"])
        return JsonResponse({})

    return JsonResponse({"error": "method not allowed"}, status=405)


def peers_view(request: HttpRequest) -> JsonResponse:
    """GET /peers?username=<name> — return live peers for the given username.

    Returns an empty list (not 404) for unknown usernames; the health-check
    endpoint (``?username=healthcheck``) relies on a 200 with an empty list.
    """
    username = request.GET.get("username", "")
    return JsonResponse({"peers": registry.fetch(username)})
