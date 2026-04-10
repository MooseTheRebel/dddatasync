import pytest

from rendezvous import registry


@pytest.fixture(autouse=True)
def clear_registry():
    """Reset the in-memory registry before and after every test."""
    registry._registry.clear()
    yield
    registry._registry.clear()
