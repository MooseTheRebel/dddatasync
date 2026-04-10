import logging
import sys
import threading
import time

from django.apps import AppConfig

logger = logging.getLogger(__name__)

PRUNE_INTERVAL_SECS: int = 60


class RendezvousConfig(AppConfig):
    name = "rendezvous"

    def ready(self) -> None:
        # Don't start background threads during pytest runs — the prune task
        # is exercised directly in tests via registry.prune().
        if "pytest" in sys.modules:
            return
        _start_prune_thread()


def _start_prune_thread() -> None:
    def _loop() -> None:
        # Import inside the thread to avoid circular-import issues at startup.
        from rendezvous.tasks import prune_expired_peers

        while True:
            time.sleep(PRUNE_INTERVAL_SECS)
            try:
                prune_expired_peers.enqueue()
            except Exception:
                logger.exception("prune task failed")

    thread = threading.Thread(target=_loop, daemon=True, name="rendezvous-prune")
    thread.start()
    logger.info("background prune thread started (interval=%ds)", PRUNE_INTERVAL_SECS)
