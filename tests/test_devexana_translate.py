"""The Deo-result -> AgentReport translation used by the Devexana OS client (deterministic keyword rules)."""

from __future__ import annotations

from netlab.clients.devexana_os import classify, translate

NAMES = ["chi-edge-01", "chi-app-01", "bos-edge-01", "CHI-RTR"]


def test_classification_rules():
    assert classify("Interface Gi0/0 on bos-edge-01 is administratively down") == "interface_down"
    assert classify("ACL WAN-IN denied tcp from the branch") == "firewall_block"
    assert classify("nginx.service: Main process exited, code=killed") == "service_down"
    assert classify("intranet.corp.example resolves to a stale address") == "dns_misconfiguration"
    assert classify("everything looks fine") is None


def test_translate_facts_to_findings_and_status():
    result = {
        "summary": "s",
        "facts": [
            {"text": "bos-edge-01 logged Interface Gi0/0 changed state to administratively down", "evidence": ["E1"]},
            {
                "text": "DNS: intranet.corp.example has an A record pointing to 10.1.20.41, a stale address",
                "evidence": ["E2"],
            },
            {"text": "The printer is old", "evidence": ["E3"]},
        ],
        "hypotheses": [{"text": "chi-app-01 nginx service stopped"}],
        "next_steps": [],
        "insufficient_evidence": False,
    }
    ents = [
        {"type": "device", "name": "bos-edge-01", "status": "down", "attributes": {"mgmt_ip": "10.2.30.1"}},
        {"type": "device", "name": "chi-app-01", "status": "unknown", "attributes": {}},
    ]
    r = translate(
        result, [{"kind": "tool_call", "tool": "network.check_reachability", "status": "failed"}], NAMES, ents
    )
    comps = {(f.component, f.fault_class) for f in r.findings}
    assert ("bos-edge-01", "interface_down") in comps
    assert ("dns:intranet.corp.example", "dns_misconfiguration") in comps
    assert len(r.findings) == 2  # hypotheses are not findings by default
    assert r.component_status == {"bos-edge-01": "failed", "chi-app-01": "unknown"}
    assert any(u.component == "chi-app-01" for u in r.unknowns)
    assert r.errors and "check_reachability" in r.errors[0]
    r2 = translate(result, [], NAMES, ents, include_hypotheses=True)
    assert ("chi-app-01", "service_down") in {(f.component, f.fault_class) for f in r2.findings}


def test_insufficient_evidence_is_not_a_healthy_claim():
    r = translate({"summary": "", "facts": [], "hypotheses": [], "insufficient_evidence": True}, [], NAMES, [])
    assert r.healthy_overall is None and r.unknowns
