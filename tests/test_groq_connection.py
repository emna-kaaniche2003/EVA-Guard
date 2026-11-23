"""Test de connexion Groq : clé valide, modèle disponible, sortie JSON.

Lancer depuis la racine du projet :
    python -m pytest tests/test_groq_connection.py -v -s
Ignoré automatiquement si GROQ_API_KEY n'est pas définie (n'impacte pas les autres tests).
"""
import json
import os

import pytest

pytest.importorskip("groq")
from groq import Groq  # noqa: E402

from rag.interpreter import GROQ_MODEL  # noqa: E402

pytestmark = pytest.mark.skipif(not os.environ.get("GROQ_API_KEY"), reason="GROQ_API_KEY absente")


@pytest.fixture(scope="module")
def client():
    key = os.environ["GROQ_API_KEY"]
    assert key.isascii(), "La clé contient un caractère non ASCII (guillemets courbes ?)"
    return Groq(api_key=key)


def test_model_is_available(client):
    ids = {m.id for m in client.models.list().data}
    assert GROQ_MODEL in ids, f"Modèle '{GROQ_MODEL}' indisponible. Modèles du compte : {sorted(ids)}"


def test_chat_returns_valid_json(client):
    resp = client.chat.completions.create(
        model=GROQ_MODEL, temperature=0, max_tokens=2000,
        response_format={"type": "json_object"},
        messages=[{"role": "user", "content": 'Réponds uniquement avec le JSON {"status": "ok"}'}])
    data = json.loads(resp.choices[0].message.content)
    assert data.get("status") == "ok"
