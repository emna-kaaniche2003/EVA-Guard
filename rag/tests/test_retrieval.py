"""Tests de récupération. Avec EVA_FAKE_EMBED=1 seuls les tests de plomberie sont significatifs ;
les tests `semantic` doivent être exécutés avec le vrai modèle d'embedding."""
import pytest

from rag.retriever import extract_metrics, retrieve

ECLIPSE_Q = ("p2p_n_peers en baisse durable, diversité des pairs en chute, p2p_sync_lag croissant, "
             "host_cpu_geth normal, latences RPC normales")
GC_Q = "pic isolé de host_cpu_geth et host_rss_geth_mb, p2p_in_kbps normal, p2p_n_peers stable"
DOS_Q = ("p2p_in_kbps en explosion, p2p_tcp_syn_recv élevé, host_cpu_geth saturé, host_rss_geth_mb en hausse, "
         "latence RPC élevée, api_ok_ratio en baisse")


def all_hits(res):
    return [h for hs in res.values() for h in hs]


def test_extract_metrics():
    assert extract_metrics(ECLIPSE_Q) == ["host_cpu_geth", "p2p_n_peers", "p2p_sync_lag"]


def test_counter_hypothesis_never_returns_predicted_type(col):
    res = retrieve(col, ECLIPSE_Q, predicted_attack="ECLIPSE")
    assert res["counter"], "aucune hypothèse alternative récupérée"
    for h in res["counter"]:
        assert h.metadata["attack_type"] not in ("ECLIPSE", "GENERIC")
        assert h.metadata["category"] in ("scenario", "attack_playbook")


def test_benign_role_only_benign_or_normal_docs(col):
    res = retrieve(col, ECLIPSE_Q, predicted_attack="ECLIPSE")
    assert res["benign"]
    for h in res["benign"]:
        assert h.metadata["category"] in ("false_positive", "normal_baseline")


def test_rules_and_exact_metric_lookup(col):
    res = retrieve(col, GC_Q, predicted_attack="DOS_P2P")
    assert all(h.metadata["category"] == "decision_rules" for h in res["rules"])
    # la définition peut être déjà remontée par un autre rôle (dédoublonnage) : on teste l'ensemble du contexte
    got = {h.metadata["metric"] for h in all_hits(res) if "metric" in h.metadata}
    assert {"host_cpu_geth", "host_rss_geth_mb", "p2p_in_kbps", "p2p_n_peers"} <= got


def test_no_duplicates_across_roles(col):
    ids = [h.id for h in all_hits(retrieve(col, DOS_Q, predicted_attack="DOS_P2P"))]
    assert len(ids) == len(set(ids))


def test_without_prediction_no_counter_role(col):
    assert "counter" not in retrieve(col, ECLIPSE_Q)


def test_support_role_returns_only_predicted_type(col):
    res = retrieve(col, ECLIPSE_Q, predicted_attack="ECLIPSE")
    assert all(h.metadata["attack_type"] == "ECLIPSE" for h in res.get("support", []))
    assert "ECLIPSE" in {h.metadata["attack_type"] for h in all_hits(res)}


def test_benign_prediction_has_no_support_role(col):
    assert "support" not in retrieve(col, ECLIPSE_Q, predicted_attack="BENIGN")


@pytest.mark.semantic
def test_eclipse_query_surfaces_eclipse_and_benign_alternative(col):
    res = retrieve(col, ECLIPSE_Q, predicted_attack="ECLIPSE", k_open=6)
    types = {h.metadata["attack_type"] for h in all_hits(res)}
    assert "ECLIPSE" in types and "BENIGN" in types and "DOS_P2P" in types


@pytest.mark.semantic
def test_gc_query_retrieves_gc_false_positive(col):
    res = retrieve(col, GC_Q, predicted_attack="DOS_P2P", k_open=6)
    ids = {h.metadata.get("scenario_id") for h in all_hits(res)}
    assert ids & {"FP_001", "SCN_BEN_GC_001"}


@pytest.mark.semantic
def test_dos_query_retrieves_dos_scenario(col):
    res = retrieve(col, DOS_Q, predicted_attack="DOS_P2P", k_open=6)
    ids = {h.metadata.get("scenario_id") for h in all_hits(res)}
    assert ids & {"SCN_DOS_001", "SCN_DOS_002"}


def test_agent_filter_restitution_returns_only_recommendations(col):
    res = retrieve(col, ECLIPSE_Q, predicted_attack="ECLIPSE", agent="restitution")
    hits = all_hits(res)
    assert hits and all(h.metadata["source"].startswith("08_") for h in hits if h.role != "metrics")


def test_agent_filter_confirmation_excludes_recommendations(col):
    hits = all_hits(retrieve(col, DOS_Q, predicted_attack="DOS_P2P", agent="confirmation"))
    assert all(not h.metadata["source"].startswith("08_") for h in hits if h.role != "metrics")
