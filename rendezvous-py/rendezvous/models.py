from django.db import models


class AccountStatus(models.TextChoices):
    PENDING = "pending", "Pending email verification"
    APPROVED = "approved", "Approved"
    BLOCKED = "blocked", "Blocked"


class UserAccount(models.Model):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    password_hash = models.CharField(max_length=255)
    status = models.CharField(
        max_length=20,
        choices=AccountStatus.choices,
        default=AccountStatus.PENDING,
    )
    verification_token = models.CharField(max_length=64, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.username} <{self.email}> [{self.status}]"


class SessionToken(models.Model):
    user = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name="tokens")
    token = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField()

    def __str__(self) -> str:
        return f"{self.user.username} — expires {self.expires_at}"
