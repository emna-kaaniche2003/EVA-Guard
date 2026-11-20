"""Fonctions d'embedding : modèle multilingue réel, ou embedder lexical déterministe (tests hors-ligne)."""
import hashlib
import math
import os
import re

DEFAULT_MODEL = os.environ.get("EVA_EMBED_MODEL", "paraphrase-multilingual-MiniLM-L12-v2")


class HashingEmbedding:
    """Embedder 'sac de mots' déterministe. Sert UNIQUEMENT à tester la plomberie (filtres, métadonnées)
    sans télécharger de modèle. Ne pas l'utiliser en production."""

    DIM = 384

    def __init__(self):
        pass

    @staticmethod
    def name() -> str:
        return "eva_hashing_embedding"

    def get_config(self):
        return {}

    @staticmethod
    def build_from_config(config):
        return HashingEmbedding()

    def is_legacy(self):
        return False

    def default_space(self):
        return "cosine"

    def supported_spaces(self):
        return ["cosine", "l2", "ip"]

    def embed_query(self, input):
        return self(input)

    def __call__(self, input):
        out = []
        for doc in input:
            vec = [0.0] * self.DIM
            for tok in re.findall(r"[a-z0-9_]+", doc.lower()):
                h = int(hashlib.md5(tok.encode()).hexdigest(), 16)
                vec[h % self.DIM] += 1.0
            norm = math.sqrt(sum(v * v for v in vec)) or 1.0
            out.append([v / norm for v in vec])
        return out


def get_embedding_function(fake: bool | None = None):
    if fake is None:
        fake = os.environ.get("EVA_FAKE_EMBED") == "1"
    if fake:
        return HashingEmbedding()
    from chromadb.utils import embedding_functions
    return embedding_functions.SentenceTransformerEmbeddingFunction(model_name=DEFAULT_MODEL)
