import logging

from django.tasks import task

from rendezvous import registry

logger = logging.getLogger(__name__)


@task
def prune_expired_peers() -> int:
    """Sweep the in-memory registry and remove expired peer records."""
    count = registry.prune()
    if count:
        logger.info("pruned %d expired peer record(s)", count)
    return count
