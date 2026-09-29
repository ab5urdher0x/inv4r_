"""INV4R API — typed request/response models (Pydantic v2)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    email: str
    password: str


class UserOut(BaseModel):
    email: str
    name: str = ""
    role: str = "Analyst"


class LoginOut(BaseModel):
    status: str = "ok"
    user: UserOut
    token: str = ""


class AuthMeOut(BaseModel):
    user: UserOut


class LogoutOut(BaseModel):
    status: str = "ok"


class OkOut(BaseModel):
    status: str = "ok"
    message: str = ""


class UserListOut(BaseModel):
    users: list[UserOut] = []
    total: int = 0


class CreateUserIn(BaseModel):
    email: str
    name: str = ""
    role: str = "Analyst"
    password: str


class ResetPasswordIn(BaseModel):
    email: str
    new_password: str


class DeleteUserIn(BaseModel):
    email: str


class AISettingsOut(BaseModel):
    mode: str = "learned"
    air_gapped: bool = True
    mappings_dir: str = ""
    min_confidence: float = 0.0
    local_llm: dict[str, Any] = {}
    cloud_llm: dict[str, Any] = {}
    note: str = ""


class StatusOut(BaseModel):
    version: str
    posture: str
    ai_mode: str
    air_gapped: bool
    total_nodes: int
    active_mapping_packs: int
    pending_mapping_packs: int
    learned_examples: int
    server_time: str = ""


class SetSettingsOut(BaseModel):
    status: str = "ok"
    settings: AISettingsOut


class FrameworkSummary(BaseModel):
    profile_id: str
    title: str = ""
    # The exact policy identifier from the profile metadata (e.g. "CIS"), used
    # as the authoritative label in the UI — never a derived description.
    framework: str = ""
    version: str = "1.0"
    description: str = ""
    control_count: int = 0


class FrameworksOut(BaseModel):
    frameworks: list[FrameworkSummary] = []
    total: int = 0


class FrameworkControlOut(BaseModel):
    control_id: str
    title: str = ""
    severity: str = "medium"
    category: str = "general"
    description: str = ""
    rationale: str = ""


class FrameworkDetailOut(BaseModel):
    """A framework's actual policy data — counts come from the profile, never
    hardcoded. Drives the interactive framework checklist."""

    profile_id: str
    title: str = ""
    framework: str = ""
    version: str = "1.0"
    description: str = ""
    control_count: int = 0
    controls: list[FrameworkControlOut] = []


class ControlDefinitionIn(BaseModel):
    """Admin-submitted control definition for the framework overlay."""

    id: str
    title: str
    severity: str = "medium"
    fact: str | None = None
    expect: dict[str, Any] = {}
    any_of: list[dict[str, Any]] = []
    all_of: list[dict[str, Any]] = []
    applicable_when: dict[str, Any] | None = None
    rationale: str = ""
    description: str = ""
    remediation: dict[str, list[str]] = {}


class VocabularyEntry(BaseModel):
    fact: str
    type: str
    description: str


class VocabularyOut(BaseModel):
    fact_version: str
    facts: list[VocabularyEntry] = []
    total: int = 0


class DeviceMetadataOut(BaseModel):
    """Device identification data (PS requirement: report device details)."""

    hostname: str = ""
    os_version: str = ""
    model_hint: str = ""
    serial: str = ""
    ip_address: str = ""
    site: str = ""
    notes: str = ""
    user_supplied: dict[str, Any] = {}
    source: str = "auto"


class NodeOut(BaseModel):
    id: str
    name: str
    path: str
    vendor: str
    platform: str
    adapter: str
    tier: int
    facts_count: int
    unknown_count: int
    coverage_level: int
    coverage_name: str = ""
    compliance_score: float = 0.0
    compliance_band: str = "unknown"
    controls_evaluated: int = 0
    controls_total: int = 0
    ip_address: str = ""
    serial: str = ""
    hardware_model: str = ""
    session_id: str = ""
    file_size: int = 0
    evidence_id: str = ""
    sha256: str = ""
    duplicate: bool = False
    error: str = ""


class NodesOut(BaseModel):
    nodes: list[NodeOut] = []
    total: int = 0


class NodeDetailFact(BaseModel):
    name: str
    value: Any = None
    status: str = "PRESENT"
    confidence: float = 0.0
    source_adapter: str = ""
    evidence_lines: list[int] = []
    scope: str = "device"
    entity: str | None = None
    derivation: str = "direct"
    evidence_texts: list[str] = []


class NodeDetailControl(BaseModel):
    control_id: str
    title: str = ""
    result: str = "UNKNOWN"
    severity: str = "medium"
    detail: str = ""
    evidence_lines: list[int] = []
    remediation: str = ""
    remediation_cli_sequence: list[str] = []
    # Control-specific context for the Evidence & Remediation view.
    framework: str = ""
    expected: str = ""
    observed: str = ""
    reason: str = ""
    has_remediation: bool = False


class NodeDetailFragment(BaseModel):
    proposal_id: str = ""
    raw_path: str = ""
    raw_text: str = ""
    category: str = "other"
    source_span: dict[str, Any] = {}
    suggested_fact: str | None = None
    suggestion_confidence: float = 0.0
    suggested_by: str = ""
    status: str = "PENDING"
    decided_fact: str | None = None
    approver: str = ""
    decided_at: str = ""


class NodeDetailOut(BaseModel):
    id: str
    name: str
    vendor: str
    platform: str
    os_version: str = ""
    model_hint: str = ""
    device_metadata: DeviceMetadataOut = DeviceMetadataOut()
    adapter: str
    tier: int
    coverage_level: int
    coverage_name: str = ""
    coverage_reasons: list[str] = []
    raw_config: str = ""
    raw_lines_count: int = 0
    hashes: dict[str, str] = {}
    evidence_id: str = ""
    provenance: list[dict[str, Any]] = []
    errors: list[str] = []
    fact_counts: dict[str, int] = {}
    facts: list[NodeDetailFact] = []
    compliance: dict[str, Any] = {}
    controls_summary: dict[str, int] = {}
    unknown_fragments: list[NodeDetailFragment] = []
    detection_reasons: list[str] = []
    candidate_vendors: list[str] = []
    detection_confidence: float = 0.0


class CategoryStats(BaseModel):
    PASS: int = 0
    FAIL: int = 0
    UNKNOWN: int = 0
    NOT_APPLICABLE: int = 0


class DeviceAssessmentOut(BaseModel):
    device_id: str = ""
    filename: str = ""
    vendor: str = ""
    platform: str = ""
    adapter: str = ""
    tier: int = 5
    facts_count: int = 0
    unknown_count: int = 0
    coverage_level: int = 0
    compliance_score: float = 0.0
    compliance_band: str = "unknown"
    controls_summary: dict[str, int] = {}
    control_results: list[dict[str, Any]] = []


class AssessOut(BaseModel):
    framework: str
    frameworks: list[str] = []
    controls: list[str] = []
    summary: dict[str, Any] = {}
    category_breakdown: dict[str, CategoryStats] = {}
    devices: list[DeviceAssessmentOut] = []
    review_status: str = "ready_for_report"
    preview: bool = False
    server_time: str = ""


class UploadResultOut(BaseModel):
    status: str = "ok"
    job_id: str = ""
    filename: str = ""
    vendor: str = ""
    platform: str = ""
    os_version: str = ""
    adapter: str = ""
    tier: int = 5
    facts_count: int = 0
    unknown_count: int = 0
    coverage_level: int = 0
    coverage_name: str = ""
    evidence_id: str = ""
    duplicate: bool = False
    duplicate_of: str = ""
    coverage_reasons: list[str] = []
    error: str = ""


class UploadOut(BaseModel):
    results: list[UploadResultOut] = []
    total: int = 0
    failed: int = 0
    duplicates: int = 0
    server_time: str = ""


class MappingPackDetails(BaseModel):
    map_id: str = ""
    vendor: str = ""
    platform: str = ""
    version: str = ""
    status: str = ""
    created_by: str = ""
    created_at: str = ""
    approved_by: str = ""
    approved_at: str = ""
    version_comment: str = ""
    rules_count: int = 0
    active_rules: int = 0
    supersedes: str = ""
    superseded_by: str = ""
    transition_state: str = ""
    decision_reason: str = ""
    transition_reason: str = ""
    replay_source: str = ""
    from_version: str = ""


class MappingsOut(BaseModel):
    packs: list[MappingPackDetails] = []
    total: int = 0
    server_time: str = ""


class MappingHistoryEntry(BaseModel):
    map_id: str
    vendor: str = ""
    platform: str = ""
    status: str
    created_by: str = ""
    created_at: str = ""
    approved_by: str = ""
    approved_at: str = ""
    rules_count: int = 0
    active_rules: int = 0
    decision_reason: str = ""
    transition_reason: str = ""


class MappingHistoryOut(BaseModel):
    history: list[MappingHistoryEntry] = []
    total: int = 0
    server_time: str = ""


class MappingDecisionOut(BaseModel):
    status: str = "ok"
    decision: str = ""
    map_id: str = ""
    pack: MappingPackDetails


class TrainSessionOut(BaseModel):
    session_id: str = ""
    vendor: str = ""
    platform: str = ""
    proposals: list[NodeDetailFragment] = []
    pending_count: int = 0


class TrainDecideIn(BaseModel):
    proposal_id: str
    decision: str = Field(default="APPROVED", pattern="^(APPROVED|REJECTED|DEFERRED)$")
    fact: str | None = None


class TrainDecideBatchIn(BaseModel):
    """Batch decisions (GUI) or a single-proposal decision (dashboard buttons)."""

    node_id: str
    decisions: list[TrainDecideIn] = Field(default_factory=list)
    proposal_id: str | None = None
    decision: str = Field(default="APPROVED", pattern="^(APPROVED|REJECTED|DEFERRED)$")
    fact: str | None = None

    @property
    def effective_decisions(self) -> list[TrainDecideIn]:
        if self.decisions:
            return self.decisions
        if self.proposal_id:
            return [TrainDecideIn(proposal_id=self.proposal_id,
                                  decision=self.decision, fact=self.fact)]
        return []


class TrainDecideOut(BaseModel):
    status: str = "ok"
    pack_written: str = ""
    decisions: int = 0
    session_id: str = ""
    pending_count: int = 0
    decided_count: int = 0


class AIImplOut(BaseModel):
    suggested: str = ""
    suggested_confidence: float = 0.0
    suggested_by: str = ""
    could_not_suggest: bool = False


class EVOut(BaseModel):
    mode: str = ""
    dataset_size: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    vocab_violations: int = 0
    per_example: list[AIImplOut] = []
    server_time: str = ""


class SettingsUpdate(BaseModel):
    mode: str | None = None
    air_gapped: bool | None = None


class CloudKeyIn(BaseModel):
    """Cloud LLM credential submission. Never echoed back in any response."""

    key: str
    provider: str = "openai"


class CloudKeyStatusOut(BaseModel):
    status: str = "ok"
    configured: bool = False
    masked: str = ""
    provider: str = ""


class ReviewNodeOut(BaseModel):
    node_id: str
    vendor: str = ""
    pending: int = 0


class ReviewStatusOut(BaseModel):
    framework: str = ""
    needs_review: bool = False
    outstanding: int = 0
    nodes: list[ReviewNodeOut] = []
    session_id: str = "all"
    backlog: int = 0


class SessionOut(BaseModel):
    id: str
    created_at: str = ""
    closed_at: str | None = None
    framework: str = ""
    status: str = "open"
    node_count: int = 0
    pass_count: int = 0
    fail_count: int = 0
    unknown_count: int = 0


class SessionsOut(BaseModel):
    sessions: list[SessionOut] = []
    total: int = 0
    current_session_id: str = ""


class SessionEndOut(BaseModel):
    status: str = "ok"
    session: SessionOut | None = None
    previous: SessionOut | None = None
    backlog: int = 0
    # Devices removed from the deployment when the session closed.
    nodes_cleared: int = 0


class ReviewItemOut(BaseModel):
    key: str
    raw_text: str = ""
    raw_path: str = ""
    category: str = "other"
    category_label: str = "Other"
    vendor: str = ""
    platform: str = ""
    suggested_fact: str | None = None
    suggestion_confidence: float = 0.0
    suggested_by: str = ""
    nodes: list[str] = []
    affected_count: int = 0
    resolved: bool = False
    # How it was resolved (APPROVED / REJECTED / DISMISSED) and the fact a
    # rejection leaves blank — so a resolved line never reads as "still unknown"
    # without saying why the verdict did not move.
    resolution: str = ""
    applied_fact: str = ""


class ReviewQueueOut(BaseModel):
    """Review queue. ``unresolved`` and ``categories`` are scoped; the
    unscoped remainder is reported as ``backlog`` so earlier sessions never
    inflate (or block) the current one."""

    items: list[ReviewItemOut] = []
    total: int = 0
    unresolved: int = 0
    categories: dict[str, int] = {}
    resolved: int = 0
    session_id: str = ""
    scope: str = "all"
    backlog: int = 0


class ReviewDecisionIn(BaseModel):
    key: str
    decision: str = Field(default="REJECTED", pattern="^(APPROVED|REJECTED|DEFERRED)$")
    fact: str | None = None


class ReviewDecideIn(BaseModel):
    decisions: list[ReviewDecisionIn] = Field(default_factory=list)


class ReviewCategoryIn(BaseModel):
    category: str
    fact: str | None = None


class ReviewDecideOut(BaseModel):
    status: str = "ok"
    applied: int = 0
    nodes_updated: int = 0
    unresolved: int = 0
    backlog: int = 0


class ReviewDismissIn(BaseModel):
    """Deliberately clear stale backlog items without recording a mapping."""

    keys: list[str] = Field(default_factory=list)


class ReviewDismissOut(BaseModel):
    status: str = "ok"
    dismissed: int = 0
    unresolved: int = 0
    backlog: int = 0


class InvariantEndpointIn(BaseModel):
    role: str
    value: str = ""
    hint: str = ""


class InvariantOut(BaseModel):
    id: str
    title: str
    description: str = ""
    source: str = ""
    source_hint: str = ""
    destination: str = ""
    destination_hint: str = ""
    protocol: str = ""
    port: int | None = None
    expected: str = "DENIED"
    # Endpoints Batfish cannot evaluate (e.g. the symbolic "management"): the
    # UI must ask the operator for the real subnet instead of the backend
    # silently widening it to 0.0.0.0/0.
    needs: list[InvariantEndpointIn] = []


class InvariantsOut(BaseModel):
    invariants: list[InvariantOut] = []


class InvariantVerifyIn(BaseModel):
    invariant_id: str
    session_id: str | None = None
    node_id: str | None = None
    # Operator-supplied endpoint overrides + optional device-level filter check.
    source: str | None = None
    destination: str | None = None
    protocol: str | None = None
    port: int | None = None
    qtype: str | None = None


class InvariantVerifyOut(BaseModel):
    invariant: InvariantOut
    result: str = "UNKNOWN"
    behaviour_status: str = "UNKNOWN"
    summary: str = ""
    explanation: str = ""
    path: list[dict[str, Any]] = []
    batfish_available: bool = False
    evidence: list[dict[str, Any]] = []
    server_time: str = ""
