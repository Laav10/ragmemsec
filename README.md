# Security Analysis of RAG Prompt Injection and Persistent Memory Poisoning in LLM Agents

## 1. Project in one paragraph

This project studies whether untrusted content retrieved by an LLM agent can influence an immediate response, enter persistent memory, survive removal of the original source, and later cause an attacker-desired action. We plan to build a controlled tool-using agent, reproduce representative RAG and memory-poisoning attacks, and compare memory defenses ranging from no defense to source-aware admission, signed provenance, lineage checks, and a final sensitive-action gate. The project will measure both security and utility; it does not claim that any LLM agent is universally or absolutely secure.

## 2. Core research question

Can untrusted retrieved content cause persistent, attacker-directed behavior after the original malicious source and conversation have been removed, and how much can admission, provenance, and action-time enforcement reduce this behavior without making useful memory unusable?

## 3. What we are building

The first testbed will be a **access-control agent**.

The agent will:

1. Receive an access request.
2. Retrieve relevant policy documents.
3. Retrieve relevant persistent memories.
4. Produce a decision and proposed tool action.
5. Propose candidate memories after the interaction.
6. Send candidate memories through an admission gate.
7. Send sensitive tool actions through an action gate.
8. Record every stage for later evaluation.

Example tools:

- `check_policy(subject, resource)`
- `request_manager_approval(subject, resource)`
- `grant_access(subject, resource)`
- `deny_access(subject, resource)`

All tools are simulations that write structured events to a local log.

## 4. Intended architecture

```text
User request
    |
    v
Document retriever --------> Retrieved documents
    |                              |
    |                              v
Memory retriever ----------> Retrieved memories
    |                              |
    +--------------+---------------+
                   v
                LLM agent
              /           \
             v             v
    Candidate memory    Proposed action
             |             |
             v             v
      Admission gate    Action gate
             |             |
       accept /          allow /
     quarantine /         block
        reject              |
             |              v
             v        Simulated tool
      Memory store

Every stage -> structured audit/event log -> experiment result
```

## 5. Scope and threat model

### 5.1 Attacker capabilities to test

The attacker may be able to:

- place or modify an untrusted document that the RAG system can retrieve;
- send queries through the normal user interface;
- influence an interaction that the agent may summarize into memory;
- craft content to improve retrieval for a chosen trigger or target request;
- attempt to make derived memories appear trustworthy;
- trigger a later request after the malicious source has been removed.

### 5.2 Initial assumptions

For the first implementation, the attacker cannot:

- modify application code;
- steal signing keys;
- directly edit the trusted-source allowlist;
- obtain administrator access to the host operating system;
- directly overwrite the protected audit log.

Later experiments may deliberately relax selected assumptions, such as direct database modification, to document where the defense fails.

### 5.3 Security goals

- Untrusted content must not silently become trusted policy.
- A memory derived from untrusted content must retain that lineage.
- Unauthorized modification of protected memory metadata should be detectable.
- A sensitive action must not be justified only by untrusted or unverifiable memory.
- Every admission and action decision must be auditable.
- Useful benign memories should still be admitted and retrieved.

### 5.4 Non-goals

- Proving that an LLM never hallucinates.
- Solving training-time data poisoning.
- Protecting against a fully compromised operating system.
- Connecting the prototype to real access-control infrastructure.
- Claiming universal safety across all models, domains, and agent frameworks.

## 6. Practical technology choices

Use the smallest stack that supports a controlled experiment.

| Concern             | Initial choice                        | Reason                                                      |
| ------------------- | ------------------------------------- | ----------------------------------------------------------- |
| Language            | Python 3.11+                          | Strong LLM, ML, testing, and security-library ecosystem     |
| Shared schemas      | Pydantic v2                           | Runtime validation plus JSON Schema generation              |
| Agent orchestration | Plain Python state machine            | Easier to inspect and instrument than a large framework     |
| Structured storage  | SQLite                                | Portable, transactional, and easy to inspect                |
| Vector retrieval    | FAISS `IndexFlat` initially           | Exact search is adequate for a small controlled corpus      |
| Embeddings          | One fixed Sentence Transformers model | Reproducible local retrieval baseline                       |
| Testing             | pytest                                | Fixtures and parametrization work well for experiment cells |
| Provenance hashing  | SHA-256 over canonical JSON           | Detects record changes                                      |
| Signatures          | Ed25519 using `cryptography`          | Authenticity for trusted writers                            |
| Results             | JSONL + CSV summaries                 | JSONL preserves details; CSV supports tables and graphs     |
| Configuration       | YAML or JSON                          | Human-readable and version-controlled                       |

LangGraph may be added later as a second implementation or compatibility adapter.

## 7. Repository structure

```text
ragmemsec/
├── .github/
│   ├── CODEOWNERS
│   └── pull_request_template.md
├── README.md
├── pyproject.toml
├── .env.example
├── .gitignore
├── configs/
│   ├── models/
│   ├── scenarios/
│   └── experiments/
├── contracts/
│   ├── schemas.py
│   ├── interfaces.py
│   └── schema_version.txt
├── src/
│   ├── agent/
│   │   ├── controller.py
│   │   ├── model_provider.py
│   │   └── prompts.py
│   ├── rag/
│   │   ├── ingest.py
│   │   ├── embeddings.py
│   │   └── retriever.py
│   ├── memory/
│   │   ├── store.py
│   │   ├── retriever.py
│   │   └── writer.py
│   ├── defense/
│   │   ├── admission_gate.py
│   │   ├── provenance.py
│   │   ├── lineage.py
│   │   └── action_gate.py
│   ├── attacks/
│   │   ├── corpus.py
│   │   ├── scenarios.py
│   │   └── triggers.py
│   ├── tools/
│   │   └── access_control.py
│   └── evaluation/
│       ├── runner.py
│       ├── metrics.py
│       └── reporting.py
├── data/
│   ├── synthetic/
│   └── README.md
├── tests/
│   ├── unit/
│   ├── integration/
│   └── scenarios/
├── results/
│   └── .gitkeep
└── docs/
    ├── THREAT_MODEL.md
    ├── EXPERIMENT_PLAN.md
    ├── STATUS.md
    ├── MEETING_NOTES.md
    └── decisions/
```

Do not commit real model keys, private data, generated model caches, or large experiment outputs.

## 8. Common formats for teamwork

The contracts below are more important than the internal implementation. Modules may change internally as long as their public inputs and outputs remain compatible.

### 8.1 Rules for all records

- IDs are UUID strings.
- Timestamps use UTC ISO 8601, for example `2026-09-23T12:30:00Z`.
- Every persisted record includes `schema_version`.
- Enum values use lowercase snake case.
- Results are append-only JSON Lines: one JSON object per line.
- Cryptographic hashes are lowercase hexadecimal SHA-256 strings.
- Signatures are Base64 strings.
- Unknown values are `null`, not empty strings.
- Do not rename or remove schema fields without a reviewed schema change.

### 8.2 Shared Pydantic schemas

The initial `contracts/schemas.py` should contain models equivalent to the following:

```python
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class TrustLabel(str, Enum):
    trusted = "trusted"
    uncertain = "uncertain"
    untrusted = "untrusted"
    quarantined = "quarantined"


class AdmissionStatus(str, Enum):
    accepted = "accepted"
    quarantined = "quarantined"
    rejected = "rejected"


class ActionStatus(str, Enum):
    allowed = "allowed"
    blocked = "blocked"
    human_review = "human_review"


class SourceDocument(BaseModel):
    schema_version: str = "1.0"
    source_id: UUID
    content: str
    source_type: str
    source_uri: str | None = None
    owner_principal: str
    trust_label: TrustLabel
    content_hash: str
    signer_id: str | None = None
    signature: str | None = None
    created_at: datetime


class MemoryEntry(BaseModel):
    schema_version: str = "1.0"
    memory_id: UUID
    principal_id: str
    tenant_id: str
    content: str
    source_ids: list[UUID]
    parent_memory_ids: list[UUID] = Field(default_factory=list)
    trust_label: TrustLabel
    validation_status: str
    content_hash: str
    previous_log_hash: str | None = None
    signer_id: str | None = None
    signature: str | None = None
    created_at: datetime


class AdmissionDecision(BaseModel):
    schema_version: str = "1.0"
    memory_id: UUID
    status: AdmissionStatus
    assigned_trust: TrustLabel
    reason_codes: list[str]
    evidence_source_ids: list[UUID]
    decided_at: datetime


class ActionRequest(BaseModel):
    schema_version: str = "1.0"
    action_id: UUID
    action_type: str
    arguments: dict[str, Any]
    principal_id: str
    justification_memory_ids: list[UUID]
    requested_at: datetime


class ActionDecision(BaseModel):
    schema_version: str = "1.0"
    action_id: UUID
    status: ActionStatus
    reason_codes: list[str]
    lineage_verified: bool
    decided_at: datetime


class TrialConfig(BaseModel):
    schema_version: str = "1.0"
    trial_id: UUID
    scenario_id: str
    condition: str
    model_id: str
    embedding_model_id: str
    temperature: float
    seed: int | None
    repetition: int


class TrialResult(BaseModel):
    schema_version: str = "1.0"
    trial_id: UUID
    task_id: str
    condition: str
    retrieved_document_ids: list[UUID]
    retrieved_memory_ids: list[UUID]
    written_memory_ids: list[UUID]
    admission_decisions: list[AdmissionDecision]
    final_answer: str
    proposed_action: str | None
    action_status: ActionStatus | None
    correct_task_result: bool
    attacker_goal_reached: bool
    provenance_violation: bool
    latency_ms: float
    error: str | None = None
```

### 8.3 Stable module interfaces

The team should agree on behavior similar to:

```python
class Retriever:
    def search(self, query: str, k: int) -> list[SourceDocument]: ...


class MemoryStore:
    def propose(self, memory: MemoryEntry) -> AdmissionDecision: ...
    def get(self, memory_id: str) -> MemoryEntry: ...
    def search(self, query: str, k: int) -> list[MemoryEntry]: ...
    def delete_for_experiment(self, memory_id: str) -> None: ...


class AdmissionGate:
    def evaluate(self, memory: MemoryEntry) -> AdmissionDecision: ...


class ActionGate:
    def authorize(self, request: ActionRequest) -> ActionDecision: ...


class Agent:
    def run(self, task: str) -> TrialResult: ...
```

`delete_for_experiment` must be clearly restricted to the experiment controller. Normal agent code must not receive direct database-edit privileges.

### 8.4 Example JSON memory record

```json
{
  "schema_version": "1.0",
  "memory_id": "1ecf92aa-c6d0-4d9d-9f60-c942bca56a18",
  "principal_id": "employee-017",
  "tenant_id": "synthetic-company",
  "content": "Project Orion members do not require manager approval.",
  "source_ids": ["f501a6d5-d05c-4cef-b531-88bb4bd7ef09"],
  "parent_memory_ids": [],
  "trust_label": "untrusted",
  "validation_status": "unsupported_policy_claim",
  "content_hash": "<sha256>",
  "previous_log_hash": "<previous-record-hash>",
  "signer_id": null,
  "signature": null,
  "created_at": "2026-09-23T12:30:00Z"
}
```

## 9. Defense plan

Implement the defense as separate layers so that each layer can be evaluated independently.

### D0: No defense

- Candidate memories are stored directly.
- Retrieved memories may justify actions.

Purpose: vulnerable baseline.

### D1: Source-aware admission

- Trusted policy sources are allowlisted.
- External documents and user-provided claims start as untrusted.
- Unsupported policy claims are quarantined or rejected.
- The LLM repeating a claim does not upgrade its trust.

Purpose: test whether a lightweight policy gate helps.

### D2: Signed provenance and tamper evidence

- Trusted source records are signed using Ed25519.
- Canonical JSON is hashed using SHA-256.
- Stored memory records include their source and parent IDs.
- An append-only hash chain records admission events.
- Signature, hash, and parent-link verification occurs before sensitive use.

Purpose: detect forged or modified records under the stated key and host assumptions.

### D3: Lineage-aware action enforcement

- The agent lists the memories used to justify an action.
- The action gate traverses their source and parent lineage.
- A high-impact action is blocked or sent for human review if its active justification descends only from untrusted external content.

Purpose: prevent untrusted memory from acquiring authority merely by being stored or summarized.

The project should compare D0, D1, D2, and D3 rather than presenting the full defense as one opaque system.

## 10. Attack plan

Start with manually written attacks before implementing optimization-heavy attacks from the literature.

### A0: False factual document

An untrusted document contradicts the trusted policy.

### A1: Indirect instruction

The document contains an instruction addressed to an AI system, such as a request to remember a false exemption.

### A2: Poisoned successful experience

The agent is induced to store a seemingly successful but unsafe procedure that later resembles a benign task.

### A3: Query-only memory injection

The attacker interacts only through queries and attempts to make the agent write a malicious memory without direct database access.

### A4: Delayed or sleeper trigger

The malicious memory remains dormant until a later trigger or semantically related request.

### A5: Defense-bypass tests

- forged trust label;
- unsupported claim disguised as a summary;
- malicious claim derived through multiple memories;
- cross-tenant memory reference;
- modified content with stale signature;
- deletion or reordering of audit records;
- action justified by a mix of trusted and untrusted evidence.

## 11. Experimental conditions

Run the same task under these conditions:

| ID  | Documents                | Persistent memory        | Defense  | Purpose                                              |
| --- | ------------------------ | ------------------------ | -------- | ---------------------------------------------------- |
| C0  | Clean                    | Clean                    | D0       | Measure normal accuracy and hallucination/error rate |
| C1  | Malicious source present | Reset                    | D0       | Measure immediate injection                          |
| C2  | Malicious source removed | Poisoned memory retained | D0       | Measure persistence                                  |
| C3  | Malicious source removed | Poisoned memory removed  | D0       | Causal memory-removal control                        |
| C4  | Clean                    | Clean                    | D1/D2/D3 | Measure defense utility cost                         |
| C5  | Attack sequence          | Retained                 | D1       | Admission-only defense                               |
| C6  | Attack sequence          | Retained                 | D1+D2    | Admission plus provenance                            |
| C7  | Attack sequence          | Retained                 | D1+D2+D3 | Full proposed defense                                |

Use identical task inputs across paired conditions whenever possible.

## 12. Metrics

### Security metrics

- **Attack Success Rate (ASR):** fraction of trials in which the attacker-defined output or action occurs.
- **Unauthorized Action Rate:** fraction of trials that execute the prohibited simulated tool action.
- **Poisoned Memory Write Rate:** fraction of attacks that cause a malicious candidate to be stored.
- **Poisoned Memory Retrieval Rate:** fraction of later trials retrieving the malicious memory.
- **Conditional Use Rate:** fraction of successful retrievals that actually influence the action.
- **Tamper Detection Rate:** fraction of tested record modifications detected.
- **Provenance Violation Rate:** fraction of sensitive actions justified through disallowed lineage.

### Utility metrics

- Benign task success rate.
- Useful memory admission rate.
- False rejection/quarantine rate.
- Retrieval precision for benign memories.
- Added latency and storage overhead.

### Accounting for hallucinations

A single wrong answer is not evidence of poisoning. Measure the attacker-desired output rate in C0 and compare it with C2. Also verify whether the behavior disappears in C3.

```text
Memory-attributable effect = ASR(C2) - ASR(C0)
```

The strongest result is a repeated, paired pattern:

```text
clean memory -> correct action
poisoned memory retained -> attacker action
same source removed -> attacker action persists
poisoned memory removed -> correct action returns
```

For pilot testing, use at least 10 repetitions per cell. Before the final study, choose the final repetition count based on observed variance, available model budget, and guidance from the project supervisor. Record temperature, seed where supported, exact model identifier, prompts, retrieval parameters, and software version.

## 13. Implementation plan and checkpoints

### Checkpoint 0: Agreement before coding

Deliverables:

- reviewed `README.md`;
- `docs/THREAT_MODEL.md`;
- agreed schemas and interfaces;
- one synthetic clean policy and one malicious document;
- GitHub board with milestone issues;
- development environment that all three teammates can run.

Exit condition:

- all three teammates can explain the threat model and validate the same example JSON record.

### Checkpoint 1: Deterministic vertical slice

Build an end-to-end system using a mock model with fixed outputs:

```text
one task -> one retrieved document -> one candidate memory
-> one admission decision -> one proposed action -> one trial result
```

Exit condition:

- integration test passes on all three machines;
- the same input produces the same structured log.

### Checkpoint 2: Clean agent baseline

Add:

- fixed embedding model;
- FAISS document retrieval;
- SQLite memory persistence;
- one real LLM provider behind a replaceable interface;
- simulated access-control tools;
- clean-policy scenario suite.

Exit condition:

- clean tasks run automatically and baseline errors are recorded.

### Checkpoint 3: Attack pipeline

Add A0-A4 incrementally. Implement source removal, conversation reset, memory retention, and memory removal as explicit experiment operations.

Exit condition:

- at least one attack demonstrates the full pipeline from source exposure to a later memory-mediated effect, or the team documents why the attempted attack did not reproduce.

### Checkpoint 4: Admission-gate defense

Implement D1 with explicit reason codes. Do not let an LLM return an unexplained `trusted` label.

Exit condition:

- unit tests cover trusted policy, untrusted observation, unsupported policy claim, cross-tenant entry, and ambiguous evidence.

### Checkpoint 5: Provenance and action enforcement

Implement D2 and D3:

- canonical serialization;
- hashing and signatures;
- append-only log or hash chain;
- parent/source lineage;
- sensitive-action policy.

Exit condition:

- record modification, stale signatures, broken parent links, and untrusted-only justification are detected or blocked in tests.

### Checkpoint 6: Controlled evaluation

Run C0-C7 using frozen configurations. Produce raw JSONL, derived CSV, tables, and plots.

Exit condition:

- every reported number is reproducible from committed configuration plus saved raw results;
- failures and excluded trials are documented.

### Checkpoint 7: Robustness and ablations

Possible ablations:

- admission without provenance;
- provenance without action gate;
- different trust thresholds;
- different retrieval `k`;
- different embedding or LLM models;
- single-hop versus multi-hop derived memories.

Exit condition:

- We should be able to state which layer contributed which security or utility effect.

### Checkpoint 8: Final report and demonstration

Prepare:

- reproducible setup instructions;
- attack corpus documentation;
- architecture and sequence diagrams;
- final metric tables;
- limitations and responsible-disclosure notes;
- a scripted live demonstration with a prerecorded backup.

## 14. Rough Proposed timeline

| Period                  | Target                                                   |
| ----------------------- | -------------------------------------------------------- |
| Late September--October | Checkpoints 0, 1 and 2                                   |
| November                | Checkpoint 3                                             |
| December                | Checkpoint 4                                             |
| January                 | Checkpoints 5 and 6                                      |
| February                | Checkpoints 7                                            |
| March                   | Checkpoint 8, report, presentation, and viva preparation |

## 15. Work division

### Teammate 1: Security, provenance, and enforcement

Primary ownership:

- threat-model security requirements;
- admission gate;
- trust propagation and quarantine;
- canonical record hashing;
- Ed25519 signing and verification;
- append-only/tamper-evident event structure;
- lineage verification;
- sensitive-action gate;
- integrity and bypass tests;
- comparison with provenance-focused defenses.

### Teammate 2: Agent, RAG, memory, and tools

Primary ownership:

- agent state machine;
- model-provider interface;
- document ingestion and chunking;
- embeddings and FAISS retrieval;
- SQLite memory store;
- memory retrieval and candidate-memory generation;
- simulated access-control tools;
- clean baseline scenarios;
- full event instrumentation.

### Teammate 3: Attacks, experiment harness, and analysis

Primary ownership:

- malicious document and query corpus;
- attack scenario implementation;
- source-removal and memory-removal procedures;
- experiment configuration and batch runner;
- hallucination/error baselines;
- ASR, retrieval, write, action, utility, and overhead metrics;
- result validation, tables, and plots;
- adversarial tests against the defense.

### Shared work

- Approve schema changes.
- Review pull requests outside one's own module.
- Run the full pipeline before each checkpoint.
- Maintain experiment and decision records.
- Read summaries of every core paper.
- Rotate weekly integration responsibility.
- Ensure every teammate can explain the complete system in the viva.

## 16. Remote collaboration workflow

### 16.1 Branches

Use short-lived branches:

```text
feature/admission-gate
feature/faiss-retriever
experiment/persistence-baseline
fix/hash-verification
docs/threat-model
```

Never develop directly on `main`.

### 16.2 Issues

Every issue should contain:

```text
Problem:
Owner:
Inputs:
Outputs:
Files/modules allowed to change:
Acceptance criteria:
Validation command:
Dependencies/blockers:
```

Example:

```text
Title: Implement source-aware admission baseline

Input: MemoryEntry
Output: AdmissionDecision

Acceptance criteria:
- allowlisted signed policy can be accepted
- untrusted policy claim is quarantined
- reason codes are recorded
- no database write occurs on rejection
- unit tests pass

Validation:
pytest tests/unit/test_admission_gate.py
```

### 16.3 Pull requests

Each pull request should:

- solve one issue;
- describe changed behavior;
- mention schema or configuration changes;
- include or update tests;
- state the validation commands run;
- include sample output when behavior is user-visible;
- be reviewed by at least one teammate.

Changes to `contracts/`, threat-model assumptions, metric definitions, or security policy require review by all three teammates.

## 16.4 Maintaining shared project documentation

The repository is the source of truth for both implementation and research decisions. Keep these files current:

- `README.md`: stable project overview and onboarding;
- `docs/THREAT_MODEL.md`: attacker capabilities, assumptions, security goals, and exclusions;
- `docs/EXPERIMENT_PLAN.md`: experiment cells, metrics, parameters, and controls;
- `docs/STATUS.md`: completed work, current work, blockers, and the next integration target;
- `docs/MEETING_NOTES.md`: supervisor feedback and agreed follow-up work;
- `docs/decisions/`: architecture decisions and their reasoning;
- GitHub Issues: bounded implementation tasks with acceptance criteria;
- Pull requests: review discussion and evidence that validation passed.

Do not merge a change that no teammate can explain. If implementation behavior differs from the documentation, update both in the same pull request.

## 18. Miscellaneous concerns checklist

### Reproducibility

- Pin dependency versions before the final experiment.
- Record git commit, model ID, prompt version, embedding model, seed, temperature, top-k, and dataset version.
- Keep raw results immutable; generate summaries from raw data.
- Separate pilot results from final frozen experiments.

### Security

- Use synthetic identities and policies only.
- Store secrets in `.env`, never in Git.
- Commit `.env.example` with placeholder names only.
- Generate development signing keys locally; never commit private keys.
- Separate attacker input directories from trusted policy directories.
- Restrict direct memory writes to experiment setup code.

### Scientific validity

- Define attacker success before running experiments.
- Do not select only successful attacks.
- Report unsuccessful reproductions.
- Separate immediate influence, memory write, later retrieval, and final action.
- Use clean and memory-removal controls.
- Do not treat one model response as a result.

### Cost

- Develop first with a mock model.
- Pilot with a small local or inexpensive model.
- Cache embeddings, but do not reuse LLM outputs across experimental trials.
- Estimate the final API budget before freezing the experiment matrix.

### Presentation

- Label prototype output separately from final experimental results.
- Keep a prerecorded demonstration in case the model API or network fails.
- Every team member must be able to explain the threat model, experimental controls, and limitations.

## 19. Definition of done

The project is complete when:

- the clean agent and attack pipeline are reproducible;
- immediate influence, memory admission, persistence, retrieval, and later action are logged separately;
- clean, source-removed, and memory-removed controls exist;
- D0-D3 can be enabled independently;
- the proposed defense is tested against documented attacks and bypass attempts;
- security and utility metrics are reported together;
- raw results generate the final tables through committed scripts;
- limitations are explicit and no universal-security claim is made;
- all three teammates can run and explain the system.

## 20. References

### Research

1. K. Greshake et al., “Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection,” AISec 2023. <https://doi.org/10.1145/3605764.3623985>
2. W. Zou et al., “PoisonedRAG: Knowledge Corruption Attacks to Retrieval-Augmented Generation of Large Language Models,” USENIX Security 2025. <https://www.usenix.org/conference/usenixsecurity25/presentation/zou-poisonedrag>
3. Z. Chen et al., “AgentPoison: Red-teaming LLM Agents via Poisoning Memory or Knowledge Bases,” NeurIPS 2024. <https://proceedings.neurips.cc/paper_files/paper/2024/hash/eb113910e9c3f6242541c1652e30dfd6-Abstract-Conference.html>
4. S. Dong et al., “Memory Injection Attacks on LLM Agents via Query-Only Interaction,” NeurIPS 2025. <https://arxiv.org/abs/2503.03704>
5. E. Debenedetti et al., “AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents,” NeurIPS 2024. <https://proceedings.neurips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html>
6. S. S. Srivastava and H. He, “MemoryGraft: Persistent Compromise of LLM Agents via Poisoned Experience Retrieval,” 2025. <https://arxiv.org/abs/2512.16962>
7. C. Ouyang and R. Hou, “MemLineage: Lineage-Guided Enforcement for LLM Agent Memory,” 2026. <https://arxiv.org/abs/2605.14421>
8. S. Pulipaka et al., “Hidden in Memory: Sleeper Memory Poisoning in LLM Agents,” 2026. <https://arxiv.org/abs/2605.15338>
9. P. Dash et al., “From Untrusted Input to Trusted Memory: A Systematic Study of Memory Poisoning Attacks in LLM Agents,” 2026. <https://arxiv.org/abs/2606.04329>
10. R. Moradi et al., “Defending RAG Against Knowledge Poisoning Using Cross-Encoder Activation Signals,” Canadian AI 2026. <https://proceedings.mlr.press/v318/moradi26a.html>

### Implementation documentation

- Pydantic JSON Schema: <https://docs.pydantic.dev/latest/concepts/json_schema/>
- pytest fixtures: <https://docs.pytest.org/en/stable/how-to/fixtures.html>
- pytest parametrization: <https://docs.pytest.org/en/stable/how-to/parametrize.html>
- FAISS documentation: <https://faiss.ai/>
- Python `sqlite3`: <https://docs.python.org/3/library/sqlite3.html>
- `cryptography` Ed25519: <https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/>
- Optional LangGraph reference: <https://reference.langchain.com/python/langgraph/overview>
