from pathlib import Path
import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def safe_compose():
    return FIXTURES / "docker-compose-safe.yml"


@pytest.fixture
def unsafe_compose():
    return FIXTURES / "docker-compose-unsafe.yml"


@pytest.fixture
def safe_dockerfile():
    return FIXTURES / "Dockerfile.safe"


@pytest.fixture
def unsafe_dockerfile():
    return FIXTURES / "Dockerfile.unsafe"
