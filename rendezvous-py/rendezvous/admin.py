from django.contrib import admin

from rendezvous.models import UserAccount


@admin.register(UserAccount)
class UserAccountAdmin(admin.ModelAdmin):
    list_display = ["username", "email", "status", "created_at"]
    list_filter = ["status"]
    search_fields = ["username", "email"]
    readonly_fields = ["created_at", "verification_token", "password_hash"]
    actions = ["approve_accounts", "block_accounts"]

    @admin.action(description="Approve selected accounts")
    def approve_accounts(self, request, queryset):
        updated = queryset.update(status="approved", verification_token="")
        self.message_user(request, f"{updated} account(s) approved.")

    @admin.action(description="Block selected accounts")
    def block_accounts(self, request, queryset):
        updated = queryset.update(status="blocked")
        self.message_user(request, f"{updated} account(s) blocked.")
