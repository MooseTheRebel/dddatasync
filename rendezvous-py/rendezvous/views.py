import json
import logging

from django.http import HttpRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from rendezvous import registry

logger = logging.getLogger(__name__)


@csrf_exempt
def register_view(request: HttpRequest) -> JsonResponse:
    """POST /register — upsert a peer.  DELETE /register — remove a peer."""
    if request.method == "POST":
        data = json.loads(request.body)
        registry.upsert(
            data["username"],
            data["node_id"],
            data["addrs"],
            data.get("relay_url"),
        )
        logger.info("registered username=%s node_id=%s", data["username"], data["node_id"])
        return JsonResponse({})

    if request.method == "DELETE":
        data = json.loads(request.body)
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
