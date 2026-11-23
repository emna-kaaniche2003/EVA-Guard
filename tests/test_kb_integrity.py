"""Tests d'intégrité de la base de connaissances (aucun modèle ni ChromaDB requis)."""
import re
from collections import Counter

import pytest

from rag.ingest import AGENTS, ALLOWED, REQUIRED_FILE_KEYS, load_chunks, load_file_chunks, parse_front_matter

EXPECTED = [
    "01_attack_eclipse.md", "02_attack_dos_p2p_flooding.md", "03_differential_diagnosis_false_positives.md",
    "04_attack_scenarios_examples.md", "05_ethereum_metrics_dictionary.md", "06_normal_behavior_baseline.md",
    "07_attack_evidence_and_decision_rules.md", "08_attack_response_and_recommendations.md",
]
METRIC_RE = re.compile(r"`((?:p2p|host|api)_[a-z0-9]+(?:_[a-z0-9]+)*)`")


def test_all_eight_files_exist(data_dir):
    missing = [f for f in EXPECTED if not (data_dir / f).exists()]
    assert not missing, f"fichiers manquants : {missing}"


@pytest.mark.parametrize("fname", EXPECTED)
def test_front_matter_valid(data_dir, fname):
    fm, _ = parse_front_matter((data_dir / fname).read_text(encoding="utf-8"))
    assert REQUIRED_FILE_KEYS <= fm.keys()
    assert fm["doc_id"] == fname[:-3]


def test_every_chunk_has_valid_metadata(data_dir):
    chunks = load_chunks(data_dir)
    assert len(chunks) > 40
    for c in chunks:
        for key, allowed in ALLOWED.items():
            assert c.metadata[key] in allowed, f"{c.id}: {key}={c.metadata[key]!r} invalide"
        assert c.metadata["source"] and c.metadata["surface"]


def test_chunk_ids_unique(data_dir):
    dup = [i for i, n in Counter(c.id for c in load_chunks(data_dir)).items() if n > 1]
    assert not dup, dup


def test_scenario_and_fp_ids_unique_and_present(data_dir):
    ids = [c.metadata["scenario_id"] for c in load_chunks(data_dir) if "scenario_id" in c.metadata]
    assert not [i for i, n in Counter(ids).items() if n > 1]
    for needed in ["FP_001", "FP_004", "FP_007", "FP_008", "SCN_ECL_001", "SCN_DOS_001", "SCN_BEN_GC_001"]:
        assert needed in ids


def test_scenarios_have_single_labelled_evidence_level(data_dir):
    sc = [c for c in load_file_chunks(data_dir / "04_attack_scenarios_examples.md")
          if c.metadata.get("scenario_id", "").startswith("SCN_") and c.metadata["scenario_id"] != "SCN_META"]
    assert len(sc) >= 10
    required = ["Niveau de preuve", "Métriques observées", "Durée de l'anomalie", "Surfaces affectées",
                "Preuves présentes", "Preuves absentes", "Diagnostic attendu"]
    for c in sc:
        assert c.metadata["evidence_level"] in {"illustrative", "simulated", "experimental"}
        for field in required:
            assert field in c.text, f"{c.id}: champ '{field}' absent"
        declared = re.search(r"Niveau de preuve\*\* : (\w+)", c.text).group(1)
        assert declared == c.metadata["evidence_level"], f"{c.id}: niveau de preuve incohérent"


def test_every_metric_used_is_in_dictionary(data_dir):
    dico = {c.metadata["metric"] for c in load_file_chunks(data_dir / "05_ethereum_metrics_dictionary.md")
            if "metric" in c.metadata}
    assert len(dico) >= 25
    used = set()
    for f in EXPECTED:
        if f.startswith("05_"):
            continue
        text = (data_dir / f).read_text(encoding="utf-8")
        used |= set(METRIC_RE.findall(re.sub(r"`(?:p2p|host|api)_[a-z0-9_]*\*`", "", text)))
    assert not used - dico, f"métriques non documentées : {sorted(used - dico)}"


def test_dictionary_fields_complete(data_dir):
    fields = ["Définition", "Unité", "Méthode de collecte", "Comportement normal",
              "Causes de hausse/baisse", "Attaques pour lesquelles"]
    for c in load_file_chunks(data_dir / "05_ethereum_metrics_dictionary.md"):
        if "metric" in c.metadata:
            for f in fields:
                assert f in c.text, f"{c.metadata['metric']}: champ '{f}' absent"


def test_false_positive_cases_cover_requested_benign_situations(data_dir):
    text = (data_dir / "03_differential_diagnosis_false_positives.md").read_text(encoding="utf-8").lower()
    for kw in ["initial sync", "garbage collection", "compaction", "redémarrage", "requête rpc", "bloc"]:
        assert kw in text, kw


def test_llm_never_confirms_rule_present(data_dir):
    t7 = (data_dir / "07_attack_evidence_and_decision_rules.md").read_text(encoding="utf-8")
    assert "agent de confirmation" in t7 and "Une seule surface anormale" in t7


def test_target_agent_valid_and_expanded(data_dir):
    for c in load_chunks(data_dir):
        agents = {a.strip() for a in c.metadata["target_agent"].split(",")}
        assert agents <= AGENTS, c.id
        for a in agents:
            assert c.metadata[f"agent_{a}"] is True


def test_recommendations_only_for_restitution(data_dir):
    for c in load_file_chunks(data_dir / "08_attack_response_and_recommendations.md"):
        assert c.metadata["target_agent"] == "restitution"


def test_section_meta_overrides_file_defaults(data_dir):
    types = {c.metadata["attack_type"] for c in load_file_chunks(data_dir / "08_attack_response_and_recommendations.md")}
    assert {"ECLIPSE", "DOS_P2P", "BENIGN"} <= types, "les commentaires <!-- meta --> ne sont pas pris en compte par section"


def test_rpc_families_distinguished_in_rules(data_dir):
    t = (data_dir / "07_attack_evidence_and_decision_rules.md").read_text(encoding="utf-8")
    assert "RPC_SYNC" in t and "RPC_LATENCE" in t and "CONFIRMABLE" in t and "CONTRADICTOIRE" in t
