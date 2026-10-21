# Architecture: who is involved and how it fits together

[日本語](ARCHITECTURE_ja.md)

This page shows the parties in the proof of concept, the flow of one audit period, how cheating is caught, and how the code is organised.

## 1. Parties and connections

An AI company records each action's fingerprint in the record ledger and keeps the content itself. Witnesses watch the ledger, and auditors examine only the actions the lottery selects. Audit results feed both fines and insurance pricing.

```mermaid
flowchart TB
    subgraph USE["Using AI"]
        direction LR
        C["AI company<br/>runs AI agents<br/>keeps action content"]
        T["Counterparty / user<br/>checks receipts and cosignatures"]
    end

    subgraph RECORD["Protecting the record"]
        direction LR
        L["Record ledger<br/>appends fingerprints, issues receipts<br/>ledger.py / merkle.py"]
        W["Witnesses<br/>universities, insurers, other labs<br/>witness.py"]
    end

    subgraph CHECK["Audit and insurance"]
        direction LR
        B["Public randomness beacon<br/>drand, NIST, etc.<br/>stand-in in the PoC"]
        AU["Auditors<br/>experts and AI<br/>audit.py"]
        I["Insurer<br/>prices premiums<br/>fines.py"]
    end

    C -- "1 action fingerprint and declared impact" --> L
    L -- "2 signed receipt" --> C
    C -- "3 AI operation + receipt" --> T
    L -- "4 tree head + consistency proof" --> W
    W -- "5 cosignatures" --> T
    B -- "6 randomness (after cosigning)" --> AU
    AU -- "7 request selected content<br/>8 fine if violation" --> C
    AU -- "9 audit results" --> I
```

## 2. One audit period

`Protocol.submit` and `Protocol.close_period` in `protocol.py` run this flow for one period.

```mermaid
sequenceDiagram
    autonumber
    participant C as AI company
    participant L as Record ledger
    participant W as Witnesses
    actor T as Counterparty
    participant B as Public randomness
    participant AU as Auditors
    participant I as Insurer

    C->>L: Append action fingerprint (salted hash) and declared impact
    L-->>C: Signed receipt
    C->>T: AI operation with receipt
    Note over T: Operations without a receipt are refused
    Note over L,W: End of period
    L->>W: Signed tree head and consistency proof
    Note over W: Check the log only appended since last time<br/>Raise an alarm if history was rewritten
    W-->>T: Cosignatures
    Note over T: Trust only records with a quorum of cosignatures (2 in the PoC)
    B-->>AU: Publish randomness (after cosigning, so companies cannot predict it)
    Note over AU: Lottery: audit probability = declared impact ÷ 1,000,000 yen<br/>(at least 0.1%, at most 100%)
    AU->>C: Request the content of selected actions
    C-->>AU: Content and salt (checked against the fingerprint)
    Note over AU: Plant fake violations to measure the detection rate
    AU->>C: If a violation is found, fine = damage ÷ (audit probability × detection rate)
    AU->>I: Audit results
    Note over I: Estimate total damage from audits alone<br/>(Horvitz–Thompson) and price the premium
```

## 3. Who cheats, and who catches it

Both AI companies and the ledger operator could cheat. Each kind of cheating has a mechanism that catches it and a fixed consequence.

```mermaid
flowchart LR
    subgraph COMPANY["AI company cheating"]
        V1["The AI commits a violation"]
        V2["Under-declares impact<br/>(to lower the audit chance)"]
        V3["Refuses to open a selected action"]
    end

    subgraph LOG["Ledger operator cheating"]
        V4["Rewrites past records"]
        V5["Shows different records to different parties<br/>(split view)"]
    end

    D1["Auditors catch it in the lottery audit<br/>detection rate corrected with fake violations"]
    D2["A witness detects it with the consistency proof<br/>one honest witness is enough"]
    D3["Witnesses compare cosignatures<br/>two roots for one size are detected"]

    R1["Fine = damage ÷ (audit probability × detection rate)<br/>expected fine equals the damage"]
    R2["Maximum fine"]
    R3["Alarm; the record is not trusted"]

    V1 --> D1
    V2 --> D1
    V3 --> D1
    D1 -- "AI violation" --> R1
    D1 -- "declaration or opening violation" --> R2
    V4 --> D2 --> R3
    V5 --> D3 --> R3
```

## 4. Code structure

Arrows mean "uses". The only cryptography is SHA-256 and Ed25519; there is no blockchain and no token.

```mermaid
flowchart TB
    DEMO["demo.py<br/>four-part demonstration"]
    PROTO["protocol.py<br/>runs one period"]
    LEDGER["ledger.py<br/>fingerprints, receipts, tree heads"]
    WIT["witness.py<br/>cosigning, rewrite and split-view detection"]
    AUD["audit.py<br/>audit probability, lottery, auditor, detection rate"]
    FINES["fines.py<br/>fine formula, total damage estimate, premium"]
    MERKLE["merkle.py<br/>Merkle tree, inclusion and consistency proofs<br/>(RFC 9162)"]
    CRYPTO["crypto.py<br/>Ed25519 signatures, canonical encoding"]

    DEMO --> PROTO
    PROTO --> FINES
    PROTO --> AUD
    PROTO --> LEDGER
    PROTO --> WIT
    WIT --> LEDGER
    LEDGER --> MERKLE
    LEDGER --> CRYPTO
    WIT --> MERKLE
    WIT --> CRYPTO
    AUD --> LEDGER
```

## PoC versus a real deployment

| Part | This PoC | Needed in a real deployment |
| --- | --- | --- |
| Record ledger | In memory, one process | A networked service with persistent storage |
| Witnesses | Three parties in the same process | A network of witnesses run by independent organisations |
| Public randomness | A stand-in derived from a fixed string | drand or the NIST Randomness Beacon |
| Auditors | Modelled as a detection probability | Real experts and AI, with measured detection rates |
| Counterparties and insurers | Verification and estimation functions | Integration into each organisation's systems |
