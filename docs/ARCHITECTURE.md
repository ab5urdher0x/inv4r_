# INV4R Architecture

INV4R normalizes heterogeneous network configuration into a single, auditable
security fact model, then evaluates that model against compliance frameworks.
The core is independent of any vendor. All vendor knowledge lives in versioned
adapters, profiles, and mapping packs.

---

## 1. System overview

```mermaid
flowchart TB
    subgraph Clients
        UI["Web dashboard<br/>React + TypeScript"]
        CLI["CLI<br/>inv4r ..."]
    end

    subgraph Service["INV4R service"]
        API["FastAPI layer<br/>auth · RBAC · REST"]
        ENGINE["Engine<br/>vendor independent pipeline"]
    end

    subgraph Data["Cognitive core"]
        DET["Detection<br/>format · vendor · platform · OS"]
        RES["Adapter resolver<br/>tiers 1 to 7"]
        NORM["Normalization<br/>section IR + declarative semantics"]
        FACTS["Canonical facts<br/>closed, scoped, versioned"]
        CTRL["Control engine<br/>CIS · NIST · STIG · ISO"]
        REP["Reporting<br/>JSON + PDF"]
    end

    subgraph External["Optional integrations"]
        BATFISH["Batfish<br/>behavioural verification"]
        LLM["Local / cloud LLM<br/>training loop only"]
    end

    STORE[("Evidence store<br/>out/")]
    MAPS[("Mapping packs<br/>mappings/")]

    UI --> API --> ENGINE
    CLI --> ENGINE
    ENGINE --> DET --> RES --> NORM --> FACTS --> CTRL --> REP
    ENGINE --> STORE
    FACTS --> MAPS
    CTRL --> API
    ENGINE -. optional .-> BATFISH
    MAPS -. candidates .-> LLM
```

---

## 2. Ingestion and normalization pipeline

Every byte of evidence takes the same path: hash, detect, resolve, parse,
normalize, then persist. Normalization is **deterministic** for known vendors,
and the AI lanes only ever touch syntax that no adapter understands.

```mermaid
flowchart TD
    A["Upload / ingest<br/>file · zip · evidence bytes"] --> B["Evidence envelope<br/>sha256 hash + dedup"]
    B --> C["Universal detection<br/>format · vendor · platform · OS"]
    C --> D{"Adapter resolver<br/>best match across tiers"}
    D -->|Tier 1| T1["Structured model<br/>OpenConfig / YANG / gNMI"]
    D -->|Tier 2| T2["Deterministic builtin<br/>vendor parser"]
    D -->|Tier 3| T3["External engine<br/>Batfish"]
    D -->|Tier 4| T4["Runtime approved<br/>mapping pack"]
    D -->|Tier 5| T5["Generic structural<br/>structure only"]
    D -->|Tier 6| T6["AI candidate<br/>proposal only"]
    D -->|Tier 7| T7["Unknown"]
    T1 & T2 & T3 & T4 --> IR["Section IR<br/>globals · interfaces · ACLs · lines"]
    IR --> SEM["Declarative semantic engine<br/>from mapping YAML"]
    SEM --> F["Canonical security facts<br/>scoped + evidenced"]
    T5 & T6 & T7 --> U["Unknown fragments<br/>preserved, never guessed"]
    F --> P[("Persisted artifacts")]
    U --> P
    U -. "human review" .-> TRAIN["Training loop"]
    TRAIN -. "approved mapping" .-> T4
```

---

## 3. Adapter tier resolution

The resolver scores every adapter and picks the lowest tier that has sufficient
confidence. A runtime mapping approved by a human (tier 4) gets a deliberate
boost, so learned knowledge wins over generic structure.

```mermaid
flowchart LR
    IN["Evidence + detection"] --> SCORE["Score each adapter<br/>can_handle()"]
    SCORE --> FILTER{"confidence >= 0.25?"}
    FILTER -->|no| NEXT["discard"]
    FILTER -->|yes| RANK["Sort by tier,<br/>then confidence<br/>tier 4 boosted"]
    RANK --> WIN["Chosen adapter"]
    WIN --> PARSE["parse()"]
    PARSE --> NORMZ["normalize()"]
```

| Tier | Adapter | Meaning |
|------|---------|---------|
| 1 | `structured_model` | OpenConfig / YANG / gNMI / NETCONF / RESTCONF |
| 2 | `deterministic_builtin` | Shipped vendor parsers (Cisco, Juniper, PAN-OS, Fortinet, Arista, SONiC, AWS SG) |
| 3 | `external_engine` | Batfish or another modeling engine |
| 4 | `runtime_approved` | Mapping packs from the training loop, approved by a human |
| 5 | `generic_structural` | Parses structure only, so semantics stay `UNKNOWN` |
| 6 | `ai_candidate` | AI proposes mappings from the closed vocabulary, and a human approves them |
| 7 | `unknown` | No safe interpretation |

---

## 4. Coverage model

Each device is placed on a coverage ladder. The report always states the level
actually achieved, so an unparsed vendor is never presented as compliant.

```mermaid
flowchart LR
    L0["Level 0<br/>raw ingestion"] --> L1["Level 1<br/>structural parsing"]
    L1 --> L2["Level 2<br/>platform identified"]
    L2 --> L3["Level 3<br/>resource normalization"]
    L3 --> L4["Level 4<br/>fact normalization"]
    L4 --> L5["Level 5<br/>compliance ready"]
    L5 --> L6["Level 6<br/>behaviour ready"]
    L6 --> L7["Level 7<br/>full assurance"]
```

---

## 5. Training loop with a human in the loop

Unknown fragments are the only input to the AI lanes. A lane produces a
*candidate*, and only an explicit human decision turns it into a deterministic
mapping. The loop cannot create an `ACTIVE` pack on its own.

```mermaid
flowchart TD
    UF["Unknown fragment"] --> PROPOSE{"Proposer lane"}
    PROPOSE -->|Lane 0| R["Deterministic rules<br/>no model · no network"]
    PROPOSE -->|Lane 1| LEARN["Learned kNN<br/>human approved mappings"]
    PROPOSE -->|Lane 2| LOCAL["Local LLM<br/>Ollama · air gap safe"]
    PROPOSE -->|Lane 3| CLOUD["Cloud LLM<br/>opt in · key + air_gapped=false"]
    R & LEARN & LOCAL & CLOUD --> CAND["Candidate proposal<br/>closed vocabulary only"]
    CAND --> HUMAN{"Human review"}
    HUMAN -->|reject| DROP["Discarded"]
    HUMAN -->|approve| PACK["Mapping pack<br/>PENDING_REVIEW"]
    PACK --> REVIEW{"Reviewer or above approves"}
    REVIEW -->|approve| ACTIVE["ACTIVE pack"]
    ACTIVE --> DETERM["Deterministic from then on"]
```

```mermaid
stateDiagram-v2
    [*] --> Proposed
    Proposed --> PendingReview: human approves (reviewer)
    Proposed --> Rejected: human rejects
    PendingReview --> Active: explicit approval by a reviewer or above
    PendingReview --> Rejected: rejected
    Active --> [*]
    Rejected --> [*]
```

---

## 6. Assessment and reporting

```mermaid
flowchart LR
    F["Canonical facts"] --> EVAL["Control engine"]
    PROF["Framework profiles<br/>CIS · NIST · STIG · ISO"] --> EVAL
    EVAL --> RESULT["Results per control<br/>PASS · FAIL · UNKNOWN"]
    RESULT --> SCORE["Weighted score bands"]
    RESULT --> REP["Reports<br/>device + fleet"]
    REP --> PDF["PDF<br/>identity · findings · remediation"]
    EVAL -. optional .-> BF["Batfish<br/>behavioural proof"]
```

---

## 7. Policy selection, evidence, and the preview lifecycle

The dashboard holds **one** policy selection, made up of the selected framework
ids, an optional control subset per framework, and the assessment scope. It
sends that selection to every evaluation endpoint. The server evaluates only
that selection, and every `ControlResult` carries the `framework` that produced
it, so aggregate counts are grouped per framework without a second evaluation.

```mermaid
flowchart LR
    SEL["One selection<br/>frameworks + controls + scope"] --> ASSESS["GET /api/assess<br/>?frameworks=&controls=<br/>&node_id= or &session_id="]
    SEL --> DETAIL["GET /api/nodes/{id}<br/>?frameworks=&controls="]
    SEL --> FW["GET /api/frameworks/{id}"]
    ASSESS --> EVAL["ControlEngine.evaluate_profiles<br/>only the selected profiles/controls"]
    DETAIL --> EVAL
    EVAL --> RES["ControlResult<br/>+ framework + expected + observed + reason"]
    RES --> OVR["Compliance Overview<br/>PASSED · FAILED · UNKNOWN per framework"]
    RES --> TBL["Control Results<br/>Control · Title · Severity · Result · Evidence"]
    TBL --> EVD["Evidence & Remediation"]
    RES --> QUEUE["Training queue<br/>grouped per uploaded configuration<br/>readable at node scope"]
```

### Unknowns are resolved before a report exists

An audit that leaves unknown lines is **unresolved**, not finished. The audit
flow reads the queue at *node scope* (`/api/review/queue?node_id=…`), so only
the configuration that was just ingested is listed, and everything else is a
`backlog` that cannot block it. The PDF stays locked until that node's queue is
clear. The backend refuses with `409` (`_require_review_clear`), and the UI only
mirrors the rule. Each decision re-evaluates the node in place, so the final
results appear without re-running the audit.

The chart on the dashboard follows the same grouping for each framework: **one
bar per selected framework, with three columns (Pass / Fail / Unknown)** on a
shared axis, and never a bucket for each control id.

### Evidence & Remediation

The `Evidence` action opens the only detailed view for a control result. It has
two panels: the **raw configuration with the exact evidence lines highlighted**
(red for FAIL, amber for UNKNOWN, green for PASS) and a **remediation** panel
written for people to read.

The left panel shows the ingested bytes, and nothing is reformatted or
re-serialized. The right panel is composed in this order:

| Block | Source |
|---|---|
| WHAT IS WRONG | The control's `observed` state, derived from the evaluated facts |
| WHY IT MATTERS | `controls/_impact_shared.yaml` (fact to impact) plus the control's `rationale` |
| WHAT SHOULD CHANGE | The control's `expected` state |
| SUGGESTED CONFIGURATION | `remediation_cli_sequence` from the control's policy data, **only** for the detected platform |

The vendor block is shown only when validated policy data defines it
(`has_remediation`). An `UNKNOWN` result never shows one, because nothing is
guessed before the mapping has been trained.

### Authoritative vs provisional results

Training does not change a verdict. A decision writes a `PENDING_REVIEW`
mapping pack, which the authoritative engine ignores. A second engine that
replays those packs (`preview=true`) predicts the outcome instead. Promoting the
pack to `ACTIVE` resets both engines, so the authoritative result updates
immediately and the operator never has to re-run the workflow.

```mermaid
flowchart TD
    D["Human training decision"] --> P["PENDING_REVIEW pack"]
    AUTH["Authoritative engine<br/>ACTIVE packs only"] --> R1["Compliance result"]
    PREV["Preview engine<br/>ACTIVE + PENDING_REVIEW"] --> R2["Provisional result<br/>labelled pending approval"]
    P --> PREV
    P -->|Reviewer or above approves| ACT["ACTIVE pack"]
    ACT --> AUTH
    ACT -. resets both engines .-> PREV
```

Learning closes the loop. A decision re-evaluates the affected configurations,
refreshes the aggregates for each selected framework, and updates the
Compliance Overview without any further interaction.

---

## 8. Normalization is documented, not surfaced as a UI

The Normalization Schema panel and the Remediation Simulation panel were
removed. Normalization itself is unchanged and lives here:

- §2 pipeline: detection, resolver, section IR, declarative semantics, then facts
- §3 adapter tiers: which tier owns which kind of input
- §4 coverage model: the level actually achieved, always stated
- `GET /api/vocabulary`: the closed, versioned fact vocabulary as data

---

## 9. Deployment topology

```mermaid
flowchart TB
    subgraph Host["Docker host"]
        subgraph Compose["docker compose network"]
            API2["inv4r-backend<br/>FastAPI + dashboard :8000"]
            BAT["batfish<br/>allinone (internal only)"]
        end
        VOL1[("inv4r-out")]
        VOL2[("inv4r-mappings")]
        VOL3[("inv4r-configs")]
        VOL4[("inv4r-users")]
    end
    BROWSER["Browser"] -->|HTTP :8000| API2
    API2 -->|Coordinator v2 REST| BAT
    API2 --- VOL1 & VOL2 & VOL3 & VOL4
```

---

## 10. Module map

```mermaid
flowchart TB
    CLI["cli.py"] --> ENGINE["engine.py"]
    API["api/"] --> ENGINE
    ENGINE --> CORE["core/<br/>envelope · model · facts · coverage<br/>sections · semantic · registry"]
    ENGINE --> DETECTION["detection/"]
    ENGINE --> ADAPTERS["adapters/<br/>resolver · builtin/* · generic_structural<br/>runtime_mapping · external_engine"]
    ENGINE --> MAPPING["mapping/<br/>proposal lifecycle"]
    ENGINE --> BEHAVIOUR["behaviour/<br/>Batfish client + engine"]
    API --> CONTROLS["controls/<br/>framework evaluation<br/>+ deterministic remediation"]
    CONTROLS --> REPORTING["reporting/<br/>assessment + PDF"]
    ADAPTERS --> AI["ai/<br/>proposer lanes"]
    AI --> TRAINING["training/<br/>human decisions"]
    TRAINING --> MAPPING
    CONTROLS --> OVERLAY["controls/#lt;profile#gt;__user.yaml<br/>control overlay added by an admin"]
    MAPPING --> PREVIEW["preview engine<br/>PENDING_REVIEW replay"]
```