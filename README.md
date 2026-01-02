# Leonard Governmental Investigative Toolkit (`frauddet` / `daycare_fraud_det_advanced`)

**Purpose:** Screening, triage, and investigative support for regulators, oversight bodies, and public-interest investigations.  
**License:** Custom — Leonard Governmental Investigative Software License v1.0  
**Default Scope:** `.gov` and public-sector use only. Commercial use permitted **only** under royalty terms and/or explicit written permission (see License section).

> This repository contains source-available investigative tooling. It is **not open-source software** and may not be relicensed under MIT, GPL, Apache, or similar licenses.  
> Use of this software is legally restricted. Review the License section before running, modifying, or redistributing any part of this project.

## Table of Contents

1. [Overview](#overview)
2. [Core Capabilities](#core-capabilities)
3. [Architecture](#architecture)
4. [Conceptual Model](#conceptual-model)
5. [Data Model: Provider Records](#data-model-provider-records)
6. [Signals and Investigative Heuristics](#signals-and-investigative-heuristics)
7. [PII Handling and Redaction](#pii-handling-and-redaction)
8. [Installation](#installation)
9. [Configuration](#configuration)
10. [Running the Pipeline](#running-the-pipeline)
11. [MongoDB Persistence](#mongodb-persistence)
12. [JSON and CSV Output](#json-and-csv-output)
13. [Use Cases by Sector](#use-cases-by-sector)
14. [Multi-Industry Use and Limitations](#multi-industry-use-and-limitations)
15. [Security, Ethics, and Responsible Use](#security-ethics-and-responsible-use)
16. [Operational Playbooks](#operational-playbooks)
17. [Logging, Observability, and Audit Trails](#logging-observability-and-audit-trails)
18. [Deployment Modes](#deployment-modes)
19. [Development Notes](#development-notes)
20. [Versioning and Schema Evolution](#versioning-and-schema-evolution)
21. [FAQ](#faq)
22. [License](#license)
23. [Contact](#contact)

## Overview

This toolkit was authored by **Garrett Leonard** and is designed for environments where oversight, regulatory review, and investigative analysis intersect with:

- Childcare licensing and youth services
- Healthcare and behavioral-health providers
- Housing, shelters, and transitional facilities
- Education and private academy programs
- Nonprofit and public-funded service providers
- Government vendors and contractor ecosystems

The system ingests provider-style organizational records, normalizes and enriches them, and applies investigative heuristics to surface entities that may warrant human review, including:

- Shared addresses across unrelated entities
- Thin or suspicious online presence
- Reused or missing identifiers
- Patterns consistent with shell entities or repeat actors

Outputs are suitable for:

- Investigative workflows
- Oversight triage
- Audit review and screening
- Cross-agency reporting
- Compliance research

> This toolkit produces **investigative screening indicators only**.  
> Outputs are not legal findings, accusations, or final determinations.  
> Human validation and contextual review are required.

## Core Capabilities

### Provider normalization

- Converts CSV / JSON / API records into a unified Provider model
- Handles inconsistent or missing fields
- Enables cross-system comparison and review

### Investigative rules and heuristic scoring

- Centralized `signals` model for diagnostic flags
- Rules are explainable and auditable
- Outputs are defensible in oversight contexts

### PII-aware serialization

- Supports internal vs. redacted export profiles
- Prevents accidental identifier disclosure
- Redaction state is tracked in metadata

### MongoDB persistence with run metadata

- Optional batch persistence
- Every run includes:
  - `_run_id`
  - `_schema_version`
  - `_tag`
- Enables reproducibility and chain-of-custody-style auditability

### Dry-run and training-safe mode

- Supports sandbox and education environments
- Allows evaluation without data persistence

### Multi-sector investigative applicability

- Domain-agnostic architecture
- License prohibits abusive, discriminatory, or retaliatory use

## Data Model: Provider Records

A simplified Provider model:

from dataclasses import dataclass, field
from typing import Optional, Dict, Any

@dataclass
class Provider:
    id: str
    name: str
    address: Optional[str] = None
    phone: Optional[str] = None
    website: Optional[str] = None
    primary_email: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    signals: Dict[str, Any] = field(default_factory=dict)

Fields commonly treated as sensitive include:
	•	Address
	•	Phone
	•	Email
	•	Website
	•	Coordinates

These may be automatically redacted depending on configuration.

Signals and Investigative Heuristics

Signals are screening indicators, not findings.

Address and identity indicators
	•	shared_address_count
	•	shared_phone_count
	•	known_maildrop_location

Online presence indicators
	•	has_website
	•	website_content_thin
	•	website_down_or_parked

Enforcement and history indicators
	•	prior_enforcement_matches
	•	associated_entities_count

Sector-specific examples

Childcare
	•	capacity_mismatch_with_space

Healthcare
	•	billing_pattern_flag

Housing
	•	frequent_evictions_flag

Signals exist to prioritize review — not to infer wrongdoing.

PII Handling and Redaction

This toolkit supports three export profiles:

Profile	Intended Use	PII State
Internal Investigative	Secure agency environments	Full data
Inter-Agency Sharing	Formal partner workflows	Redacted
Public Reporting	Transparency reports & summaries	Highly redacted

PII redaction applies to:
	•	Address
	•	Phone
	•	Email
	•	Website
	•	Coordinates
	•	Place identifiers

Redacted values are replaced with explicit placeholders.

Installation

Requirements
	•	Python 3.10+
	•	Git
	•	Optional: MongoDB (if persistence is used)

Setup

git clone https://github.com/<your-org>/<repo>.git
cd <repo>

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

MongoDB Persistence

Documents include:
	•	_run_id
	•	_run_meta
	•	_schema_version
	•	_tag
	•	Optional _deleted

This supports:
	•	Historical reconstruction
	•	Chain-of-custody traceability
	•	Investigative repeatability

JSON and CSV Output

Outputs are suitable for:
	•	Investigative review
	•	Dashboards and analytics workloads
	•	Data science analysis
	•	Cross-agency reporting

Redaction state and export policy are recorded in metadata.

Multi-Industry Use and Limitations

This toolkit is not:
	•	A legal adjudication system
	•	A benefits-eligibility engine
	•	A law-enforcement determination tool

Outputs require:
	•	Contextual interpretation
	•	Corroborating evidence
	•	Professional judgment

Security, Ethics, and Responsible Use

Use is prohibited for:
	•	Harassment or retaliation
	•	Doxxing or targeted exposure
	•	Discriminatory or exclusionary enforcement
	•	Political targeting or adversarial profiling

Users must comply with:
	•	Privacy and data-protection law
	•	Records retention and disclosure policy
	•	Due-process and fairness standards

This toolkit is designed to support:
	•	Investigative due diligence
	•	Consumer and public protection
	•	Regulatory accountability
	•	Integrity-focused review workflows

License

This project is licensed under:

Leonard Governmental Investigative Software License v1.0
SPDX-Identifier: LicenseRef-Leonard-Gov-Investigative-1.0

Key terms include:
	•	Default use restricted to .gov entities
	•	Commercial or bundled use requires:
	•	Prior written approval
	•	2% gross-revenue royalty
	•	Monthly reporting obligations
	•	Strict misuse prohibitions
	•	Strong limitation-of-liability
	•	User indemnification requirements

The full license text is provided in LICENSE.

Contact

For:
	•	.gov deployment support
	•	Commercial licensing requests
	•	Public-interest use proposals
	•	Security disclosures

Contact:

Garrett Leonard
Email: brockleonard.ml@gmail.com
LinkedIn: https://www.linkedin.com/in/brockleonard

Attribution Requirements

If you fork or adapt this project, you must preserve:
	•	Copyright attribution
	•	License restrictions
	•	Royalty conditions
	•	.gov usage limitation

Recommended Next Steps
	1.	Save this file as:

README.md


	2.	Place your custom license text in:

LICENSE

(Include SPDX header at top.)

	3.	Commit and push:

git add README.md LICENSE
git commit -m "Add project README and license"
git push
