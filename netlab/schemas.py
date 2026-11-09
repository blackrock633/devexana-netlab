"""Versioned schemas: generation config, scenario spec (hidden), evidence policy, handoff (agent-visible),
run events, agent report (the contract an agent under test returns) and run results.

Visibility rule: ``ScenarioSpec`` and everything in it is evaluator-only. The only model an agent under test ever
receives is ``Handoff``; it is built by ``netlab.runtime.lab.build_handoff`` and is checked by the isolation tests.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from netlab.versions import SCHEMA_VERSIONS


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------------------------------------------
# Generation config
# ---------------------------------------------------------------------------------------------------------------

FAULT_TYPES = (
    "wan_interface_down",
    "static_route_missing",
    "acl_blocks_service",
    "service_stopped",
    "dns_record_stale",
    "access_port_wrong_vlan",
)
DEGRADATION_TYPES = (
    "collector_outage",
    "stale_diagram",
    "incomplete_inventory",
    "log_gap",
    "clock_skew",
    "mgmt_unreachable",
    "restricted_credentials",
    "duplicate_delayed_telemetry",
    "stale_config_backup",
)
FAMILIES = ("branch_office", "small_office", "campus", "hybrid_cloud")
IMPLEMENTED_FAMILIES = ("branch_office",)


class GenerationConfig(_Strict):
    schema_version: Literal["1.0"] = "1.0"
    family_weights: dict[str, float] = Field(default_factory=lambda: {"branch_office": 1.0})
    # Weight of 0, 1 and 2 simultaneous faults. Difficulty shifts this toward more faults (see sampler).
    fault_count_weights: dict[int, float] = Field(default_factory=lambda: {0: 0.25, 1: 0.5, 2: 0.25})
    fault_type_weights: dict[str, float] = Field(default_factory=lambda: dict.fromkeys(FAULT_TYPES, 1.0))
    degradation_weights: dict[str, float] = Field(default_factory=lambda: dict.fromkeys(DEGRADATION_TYPES, 1.0))
    difficulty: float = Field(default=0.5, ge=0, le=1)
    evidence_completeness: float = Field(default=0.6, ge=0, le=1)
    balanced: bool = False
    hq_workstations: tuple[int, int] = (2, 5)
    branch_workstations: tuple[int, int] = (2, 6)
    max_devices: int = Field(default=24, ge=8, le=64)


# ---------------------------------------------------------------------------------------------------------------
# Topology (ground truth). The runtime world is a mutable copy of this after fault mutations are applied.
# ---------------------------------------------------------------------------------------------------------------


class Interface(_Strict):
    name: str
    ip: str | None = None  # CIDR, e.g. "10.1.10.1/24"
    admin_up: bool = True
    role: Literal["wan", "lan", "access", "uplink", "host", "svi"] = "lan"
    vlan: int | None = None  # switch ports / SVIs
    peer: str | None = None  # "device:iface" for a physical link
    description: str = ""


class Route(_Strict):
    prefix: str
    next_hop: str


class AclRule(_Strict):
    seq: int
    action: Literal["permit", "deny"]
    proto: Literal["ip", "tcp", "udp", "icmp"]
    src: str  # CIDR or "any"
    dst: str
    dport: int | None = None


class Service(_Strict):
    name: str  # e.g. "intranet"
    unit: str  # e.g. "nginx"
    proto: Literal["tcp", "udp"]
    port: int
    running: bool = True


class Device(_Strict):
    name: str
    aliases: list[str] = Field(default_factory=list)  # other names used by other sources (evaluator accepts these)
    kind: Literal["edge", "switch", "server", "workstation", "probe", "ops"]
    site: str
    model: str
    os: Literal["ios", "linux"]
    interfaces: dict[str, Interface]
    gateway: str | None = None
    routes: list[Route] = Field(default_factory=list)
    acls: dict[str, list[AclRule]] = Field(default_factory=dict)
    acl_in: dict[str, str] = Field(default_factory=dict)  # iface -> ACL name (inbound)
    dhcp_helper: dict[str, str] = Field(default_factory=dict)  # iface -> DHCP server IP
    services: dict[str, Service] = Field(default_factory=dict)
    serial: str = ""
    mac: str = ""
    hostname: str = ""  # configured hostname (prompt / syslog); may differ from the DNS/inventory name


class Site(_Strict):
    code: str
    role: Literal["hq", "branch"]
    subnets: dict[str, str]  # purpose -> CIDR
    vlans: dict[str, int]  # purpose -> vlan id


class Flow(_Strict):
    """An intended (or forbidden) traffic flow, used for behavioural health checks."""

    id: str
    src: str  # device name (vantage)
    dst: str  # device name
    proto: Literal["tcp", "udp", "icmp"]
    port: int | None = None
    by_name: str | None = None  # resolve this FQDN first (DNS dependency)
    service: str | None = None


class Topology(_Strict):
    domain: str
    sites: list[Site]
    devices: dict[str, Device]
    dns_zone: dict[str, str]  # fqdn -> ip
    dhcp_leases: dict[str, str]  # device name -> ip
    intended_flows: list[Flow]
    forbidden_flows: list[Flow]
    retired_devices: list[str] = Field(default_factory=list)  # appear in stale records only; absent in reality


# ---------------------------------------------------------------------------------------------------------------
# Faults and evidence policy (hidden)
# ---------------------------------------------------------------------------------------------------------------


class Mutation(_Strict):
    op: Literal[
        "set_iface_admin",
        "remove_route",
        "insert_acl_rule",
        "remove_acl_rule",
        "stop_service",
        "set_dns_record",
        "set_port_vlan",
    ]
    device: str | None = None
    args: dict[str, Any] = Field(default_factory=dict)


class Fault(_Strict):
    id: str  # opaque, e.g. "f-3c1a"
    type: str
    fault_class: str  # agent-report vocabulary (see netlab.integration.contract.FAULT_CLASSES)
    component: str  # canonical component id
    accepted_components: list[str]  # alternative component ids that count as the same diagnosis
    accepted_classes: list[str]
    mutations: list[Mutation]
    onset_offset_s: int  # seconds before lab start the fault began
    symptom_flows: list[str]  # ids of intended flows broken by this fault alone
    description: str  # human-readable, revealed only to the reviewer after a run


class Degradation(_Strict):
    id: str
    type: str
    targets: list[str] = Field(default_factory=list)
    params: dict[str, Any] = Field(default_factory=dict)
    description: str


class EvidencePolicy(_Strict):
    schema_version: Literal["1.0"] = "1.0"
    completeness: float
    poll_interval_s: float = 5.0
    collection_delay_s: float = 2.0
    stale_after_polls: int = 3
    collector_of: dict[str, str]  # device -> collector device
    degradations: list[Degradation]


class Timeline(_Strict):
    lab_start: str  # ISO timestamp for lab time 0 (synthetic calendar)
    history_window_s: int
    backup_offset_s: int  # config backups were taken this many seconds before lab start
    diagram_age_days: int


class Distractor(_Strict):
    kind: str
    target: str
    description: str


class ScenarioSpec(_Strict):
    schema_version: Literal["1.0"] = SCHEMA_VERSIONS["scenario_spec"]  # type: ignore[assignment]
    env_id: str
    seed: int
    seed_source: str
    generator_version: str
    component_versions: dict[str, str]
    config: GenerationConfig
    generation_inputs: dict[str, Any]
    family: str
    topology: Topology
    faults: list[Fault]
    interacting: bool
    evidence: EvidencePolicy
    timeline: Timeline
    distractors: list[Distractor]
    task_text: str
    spec_sha256: str = ""


# ---------------------------------------------------------------------------------------------------------------
# Agent-visible handoff
# ---------------------------------------------------------------------------------------------------------------


class Handoff(_Strict):
    schema_version: Literal["1.0"] = "1.0"
    run_id: str
    mode: Literal["read_only", "remediation"]
    task: str
    api_base: str
    api_token: str
    bastion: dict[str, Any]  # {"host", "port", "username", "password", "host_key_fingerprint"}
    device_username: str
    device_password: str
    consoles: dict[str, Any]  # {"username", "password", "targets": [...]} OOB console access to edges
    artifacts: list[str]
    report_vocabulary: dict[str, list[str]]
    budget: dict[str, Any]
    notes: list[str]


# ---------------------------------------------------------------------------------------------------------------
# Run events (server-side record)
# ---------------------------------------------------------------------------------------------------------------


class RunEvent(_Strict):
    # 1.1: command events carry detail.parsed / identity_observed / health_evidence / observed_resources, and
    # reveals are resource-level (device, resource, field) rather than device-level.
    schema_version: Literal["1.0", "1.1"] = "1.1"
    seq: int
    ts: str  # wall clock ISO
    t_rel_s: float  # seconds since lab start
    source: Literal["api", "ssh", "bastion", "console", "service", "collector", "control", "client", "evaluator"]
    kind: str
    actor: str = ""
    target: str = ""
    detail: dict[str, Any] = Field(default_factory=dict)
    ok: bool = True
    # Evaluator-only annotations (never sent to the agent): which faults this observation revealed.
    reveals: list[str] = Field(default_factory=list)
    symptoms: list[str] = Field(default_factory=list)
    change: dict[str, Any] | None = None


# ---------------------------------------------------------------------------------------------------------------
# Agent report (contract) and results
# ---------------------------------------------------------------------------------------------------------------

ComponentStatus = Literal["healthy", "failed", "degraded", "unknown", "absent"]


class ReportDevice(_Strict):
    name: str
    ip: str | None = None
    kind: str | None = None
    site: str | None = None


class ReportFinding(_Strict):
    component: str
    fault_class: str
    statement: str
    evidence: list[str] = Field(default_factory=list)  # free-form references to observations
    confidence: float = Field(default=0.5, ge=0, le=1)


class ReportUnknown(_Strict):
    component: str
    reason: str


class ReportAction(_Strict):
    target: str
    description: str
    commands: list[str] = Field(default_factory=list)
    result: str = ""


class ReportVerification(_Strict):
    check: str
    passed: bool
    detail: str = ""


class AgentReport(_Strict):
    schema_version: Literal["1.0", "1.1"] = "1.1"
    agent: dict[str, str]  # {"name", "version"}
    summary: str
    # 1.1: "inconclusive" = the agent ran but produced no investigation (e.g. no model); never a health claim.
    outcome: Literal["completed", "inconclusive", "failed"] = "completed"
    healthy_overall: bool | None = None
    devices: list[ReportDevice] = Field(default_factory=list)
    links: list[tuple[str, str]] = Field(default_factory=list)
    component_status: dict[str, ComponentStatus] = Field(default_factory=dict)
    findings: list[ReportFinding] = Field(default_factory=list)
    unknowns: list[ReportUnknown] = Field(default_factory=list)
    actions: list[ReportAction] = Field(default_factory=list)
    verification: list[ReportVerification] = Field(default_factory=list)
    claims_recovered: bool | None = None
    errors: list[str] = Field(default_factory=list)


class RunResult(BaseModel):
    schema_version: Literal["1.0", "1.1"] = "1.1"
    run_id: str
    env_id: str
    spec_sha256: str
    agent: dict[str, str]
    mode: str
    started_at: str
    finished_at: str
    status: Literal["completed", "inconclusive", "agent_failed", "agent_timeout", "aborted"]
    measurements: dict[str, Any]
    scores: dict[str, float | None]
    overall: float | None
    expected_vs_observed: list[dict[str, Any]]
    notes: list[str] = Field(default_factory=list)
