from pathlib import Path

import pytest

from rag.embeddings import get_embedding_function
from rag.ingest import build

DATA = Path(__file__).resolve().parent.parent / "rag" / "data"


@pytest.fixture(scope="session")
def data_dir():
    return DATA


@pytest.fixture(scope="session")
def col(tmp_path_factory):
    ef = get_embedding_function()
    return build(DATA, tmp_path_factory.mktemp("chroma"), "eva_test", reset=True, ef=ef)
