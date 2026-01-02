Great — the Markdown you provided is already in a GitHub-ready format. To make sure it renders cleanly and works well as a project README on GitHub, here are a few recommendations and final checks you should perform before committing it.

Below is a refined, GitHub-optimized version of your README section — properly structured, consistent in heading hierarchy, and formatted for repository presentation.

You can paste this directly into README.md.

⸻


# Leonard Governmental Investigative Toolkit (`frauddet`)

> **Purpose:** Screening, triage, and investigative support for regulators, oversight bodies, and public-interest investigations.  
> **License:** Custom — **Leonard Governmental Investigative Software License v1.0**  
> **Default scope:** `.gov` and public-sector use only. Commercial use allowed **only** under royalty terms and/or explicit written permission (see [License](#license)).

---

## 📌 Repository Status Notice

This repository contains source-available investigative tooling.  
It is **not open-source software** and may not be relicensed under MIT, GPL, Apache, or similar licenses.

Use of this software is legally restricted.  
See the **License** section before running, modifying, or redistributing any part of this project.

---

## Table of Contents

1. [Overview](#overview)  
2. [Core Capabilities](#core-capabilities)  
3. [Architecture](#architecture)  
4. [Conceptual Model](#conceptual-model)  
5. [Data Model: Provider Records](#data-model-provider-records)  
6. [Signals and Investigative Heuristics](#signals-and-investigative-heuristics)  
7. [PII Handling & Redaction](#pii-handling--redaction)  
8. [Installation](#installation)  
9. [Configuration](#configuration)  
10. [Running the Pipeline](#running-the-pipeline)  
11. [MongoDB Persistence](#mongodb-persistence)  
12. [JSON / CSV Output](#json--csv-output)  
13. [Use Cases by Sector](#use-cases-by-sector)  
14. [Multi-Industry Use & Limitations](#multi-industry-use--limitations)  
15. [Security, Ethics, and Responsible Use](#security-ethics-and-responsible-use)  
16. [Operational Playbooks](#operational-playbooks)  
17. [Logging, Observability, and Audit Trails](#logging-observability-and-audit-trails)  
18. [Deployment Modes](#deployment-modes)  
19. [Development Notes](#development-notes)  
20. [Versioning and Schema Evolution](#versioning-and-schema-evolution)  
21. [FAQ](#faq)  
22. [License](#license)  
23. [Contact](#contact)

---

## Overview

This repository contains an investigative and fraud-screening toolkit authored by **Garrett Leonard**. It is designed for environments where investigative, regulatory, or oversight work intersects with:

- Childcare licensing and oversight  
- Healthcare & behavioral health providers  
- Housing, shelters, & transitional facilities  
- Education and private academy programs  
- Nonprofits receiving public funds  
- Contractors and third-party service providers to government agencies  

The system ingests provider-style organizational records, normalizes them, enriches them, and applies investigative heuristics to surface entities that may warrant human review, including:

- Shared addresses across unrelated entities  
- Thin or suspicious online presence  
- Reused or missing identifiers  
- Patterns suggesting shell entities or repeat serial actors  

Output formats include:

- JSON for investigative workflows & analytic dashboards  
- Optional CSV exports for auditors & inspectors  
- MongoDB collections tagged with run metadata for traceability

> This toolkit produces **investigative screening signals only** — not legal findings or accusations. Human verification is required.

---

## Core Capabilities

### Provider normalization
- Converts raw CSV / JSON / API input into a unified `Provider` model
- Handles missing or inconsistent field structures
- Provides a common cross-system comparison schema

### Investigative rules & heuristic scoring
- Centralized `signals` dictionary for diagnostic indicators
- Rules are intentionally explainable & auditable
- Outputs can be justified in regulatory or evidentiary contexts

### PII-aware serialization
- Supports **full internal records** and **redacted export profiles**
- Prevents accidental exposure of sensitive identifiers

### MongoDB persistence & run metadata
- Batch writes with configurable write modes
- Each run is tagged and reconstructable for audit review

### Dry-run & safe evaluation mode
- Enables training, sandboxing, and test pipelines
- Produces logs without persisting records

### Multi-sector investigative applicability
- Domain-agnostic core architecture
- License prohibits abusive, discriminatory, or retaliatory use

---

## Data Model: Provider Records

A simplified `Provider` model:

```python
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

Fields commonly treated as sensitive:
	•	Address
	•	Phone
	•	Email
	•	Website
	•	Coordinates

These may be automatically redacted depending on configuration.

⸻

Signals and Investigative Heuristics

Signals are structured analytic hints — not findings. Examples:

Address & identity indicators
	•	shared_address_count
	•	shared_phone_count
	•	known_maildrop_location

Online presence indicators
	•	has_website
	•	website_content_thin
	•	website_down_or_parked

Enforcement & history indicators
	•	prior_enforcement_matches
	•	associated_entities_count

Sector-specific flags (examples)

Childcare
	•	capacity_mismatch_with_space

Healthcare
	•	billing_pattern_flag

Housing
	•	frequent_evictions_flag

Flags are used to prioritize human review — not to conclude wrongdoing.

⸻

PII Handling & Redaction

This toolkit supports three standard export profiles:

Profile	Intended Use	PII State
Internal Investigative	Secure agency systems	Full data
Inter-Agency Sharing	Controlled partners	Redacted
Public Reporting	Transparency reports	Highly redacted

PII redaction applies to:
	•	address
	•	phone
	•	email
	•	website
	•	coordinates
	•	place identifiers

Redacted values are replaced with explicit placeholders.

⸻

Installation

Requirements:
	•	Python 3.10+
	•	Git
	•	Optional: MongoDB for persistence

git clone https://github.com/<your-org>/<repo>.git
cd <repo>

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt


⸻

MongoDB Persistence

Documents are persisted with:
	•	_run_id
	•	_run_meta
	•	_schema_version
	•	_tag
	•	optional _deleted

Every run is independently reconstructable.

This enables:
	•	chain-of-custody style auditability
	•	historical comparison
	•	investigative repeatability

⸻

JSON / CSV Output

Exports are suitable for:
	•	forensic review
	•	dashboards
	•	data science workflows
	•	cross-agency reporting

Redaction state is preserved in output metadata.

⸻

Multi-Industry Use & Limitations

This toolkit is screening software, not:
	•	a legal adjudication system
	•	a benefits-eligibility engine
	•	a law enforcement determination tool

Outputs require:
	•	contextual analysis
	•	corroborating evidence
	•	professional judgment

⸻

Security, Ethics & Responsible Use

Use is prohibited for:
	•	harassment
	•	retaliation
	•	doxxing
	•	discrimination
	•	targeted harassment campaigns

Users must comply with:
	•	privacy + data protection law
	•	records handling requirements
	•	fair-process & due-process standards

This toolkit is explicitly designed to support:
	•	investigative due diligence
	•	consumer protection
	•	regulatory accountability
	•	public integrity workflows

⸻

License

This project is licensed under:

Leonard Governmental Investigative Software License v1.0
SPDX-Identifier:

LicenseRef-Leonard-Gov-Investigative-1.0

Key terms include:
	•	Default use restricted to .gov entities
	•	Commercial & bundled use requires:
	•	prior written approval
	•	2% gross-revenue royalty
	•	monthly reporting obligations
	•	Strict misuse prohibitions
	•	Strong limitation-of-liability
	•	User indemnification requirements

The full license text is provided in LICENSE.

⸻

Contact

For:
	•	.gov deployment support
	•	commercial licensing inquiries
	•	public-interest usage requests
	•	security disclosures

Contact:

Garrett Leonard
Email: brockleonard.ml@gmail.com
LinkedIn: https://www.linkedin.com/in/brockleonard

If you fork or adapt this project, you must preserve:
	•	copyright attribution
	•	license restrictions
	•	royalty conditions
	•	.gov usage limitation

---

## Next steps I recommend

If you're posting to GitHub:

1) Make sure the file name is exactly:

README.md

2) Place your custom license text in:

LICENSE

(with SPDX header at top)

3) Commit and push:

```bash
git add README.md LICENSE
git commit -m "Add project README and license"
git push


⸻

If you want, I can also:
	•	generate a CONTRIBUTING.md
	•	add SECURITY.md for disclosures
	•	create issue templates
	•	prepare a GitHub project description blurb
	•	generate .github policy files

Just tell me 👍
