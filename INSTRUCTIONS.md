# Daycare Fraud Scanner (Advanced)  
`daycare_fraud_scanner_advanced.py`

High-impact investigative tool for discovering, enriching, and risk-scoring daycare and childcare providers, with optional MongoDB persistence and JSON Schema export.

> **Important:** This tool is part of a broader investigative ecosystem and is governed by the project Code of Conduct, Threat Model, and Risk Assessment (`CODE_OF_CONDUCT.md`). You must read and agree to that document before running this tool in any real-world context.

## 1. Overview

`daycare_fraud_scanner_advanced.py` automates:

- Discovery of childcare providers, primarily via Google Places.
- Enrichment of providers with:
  - Google Place Details (address, status, reviews, activity signals).
  - Website content (if enabled).
  - Social and government records (currently scaffolds).
- Computation of:
  - Fraud and legitimacy scores.
  - Peer-relative activity signals (city-level outliers).
  - Risk tier (critical, high, medium, low, unknown).
- Classification of providers into:
  - `licensed_and_active` (legit).
  - `licensed_but_not_listed` (fraud, per taxonomy).
  - `unlicensed_but_listed` (fraud).
  - `unknown` (needs review).
- Export of:
  - Grouped JSON by state / county / city.
  - NDJSON (line-per-provider).
  - Evidence NDJSON (per-evidence item).
  - Optional CSV summary.
  - Optional high-risk-only NDJSON.
  - Optional MongoDB persistence and JSON Schemas for Atlas or on-prem.

This script is designed as an **evidence collection scaffold**, not a final adjudication system. It produces **signals**, not legal determinations.

## 2. Prerequisites

### 2.1 Python Version

- Python 3.9 or newer is recommended.

### 2.2 Required Python Packages

Install core dependencies:

pip install requests googlemaps beautifulsoup4

Optional (for MongoDB integration):

pip install pymongo

2.3 API Keys

You must provide a Google Maps API key with Places and Place Details enabled.

Set via environment variable:

export GOOGLE_MAPS_API_KEY="YOUR_REAL_API_KEY"

If not set, the script will default to "YOUR_GOOGLE_MAPS_API_KEY" and will not successfully call Google APIs.

3. Environment Variables

The script can be configured via environment variables and/or CLI flags. CLI flags override environment defaults.

3.1 Core Search Configuration
	•	GOOGLE_MAPS_API_KEY
Google Maps / Places API key.
	•	DCS_SEARCH_REGION
Default search region used if --region is not provided.
Default: "Washington State".

3.2 Output and Evidence Directories
	•	OUTPUT_DIR (internal default: "output")
Base directory for JSON, NDJSON, CSV outputs. Overridable via --output-dir.
	•	EVIDENCE_DIR (internal default: "evidence")
Directory for evidence NDJSON files. Overridable via --evidence-dir.

3.3 Throttling and Timeouts
	•	API_SLEEP_SECONDS
Delay between Google API calls. Overridable via --api-sleep.
	•	GOOGLE_REVIEW_RECENT_DAYS
Window of days considered “recent” for reviews. Overridable via --review-recent-days.
	•	HTTP_TIMEOUT
Website fetch timeout in seconds. Overridable via --http-timeout.

3.4 MongoDB Integration

Used when --mongo-enable is passed:
	•	DCS_MONGO_URI
Default Mongo URI, e.g. mongodb://localhost:27017 or Atlas mongodb+srv://....
	•	DCS_MONGO_DB
Database name. Default: daycare_fraud_scanner.
	•	DCS_MONGO_PROVIDERS_COLL
Providers collection name. Default: providers.
	•	DCS_MONGO_EVIDENCE_COLL
Evidence collection name. Default: evidence.
	•	DCS_MONGO_RUNS_COLL
Runs metadata collection name. Default: runs.
	•	Further tuning options (connection and pooling):
	•	DCS_MONGO_CONNECT_TIMEOUT_MS
	•	DCS_MONGO_SOCKET_TIMEOUT_MS
	•	DCS_MONGO_MAX_POOL_SIZE
	•	DCS_MONGO_MIN_POOL_SIZE
	•	DCS_MONGO_RETRY_WRITES
	•	DCS_MONGO_COMPRESSORS
	•	DCS_MONGO_READ_PREFERENCE
	•	DCS_MONGO_WRITE_CONCERN
	•	DCS_MONGO_TLS
	•	DCS_MONGO_TLS_CA_FILE
	•	DCS_MONGO_REPLICA_SET
	•	DCS_MONGO_INDEX_BOOTSTRAP
	•	DCS_MONGO_SCHEMA_VERSION
	•	DCS_MONGO_ALLOW_SCHEMA_DOWNGRADE
	•	DCS_MONGO_BATCH_SIZE
	•	DCS_MONGO_DRY_RUN
	•	DCS_MONGO_SOFT_DELETE

4. Basic Usage

From the directory containing daycare_fraud_scanner_advanced.py:

python daycare_fraud_scanner_advanced.py \
  --region "Washington State" \
  -k daycare -k "child care" \
  --output-dir out \
  --no-website \
  --log-level DEBUG \
  --min-fraud-score 3.0 \
  --risk-tier-include critical --risk-tier-include high \
  --print-top-n 25 \
  --redact-pii

4.1 Minimal Example

Run with defaults and built-in keywords:

python daycare_fraud_scanner_advanced.py \
  --region "Washington State"

This will:
	•	Discover providers via Google Places using built-in keywords.
	•	Enrich, classify, and score providers.
	•	Write grouped JSON, NDJSON, evidence NDJSON, and CSV summary.
	•	Print basic logs at INFO level.

4.2 Discovery-Only Dry Run

To test discovery without enrichment or scoring:

python daycare_fraud_scanner_advanced.py \
  --region "Washington State" \
  --dry-run

This writes providers_discovered.ndjson and skips:
	•	Google details enrichment.
	•	Website fetching.
	•	Social and government lookups.
	•	Classification, scoring, and risk tiers.

4.3 Human Summary Mode

To get a quick text summary plus normal outputs:

python daycare_fraud_scanner_advanced.py \
  --region "Washington State" \
  --print-summary-only \
  --print-top-n 20

This prints:
	•	Count per status class.
	•	Count per risk tier.
	•	A table of top N most suspicious providers by fraud_score.

5. CLI Options

Run:

python daycare_fraud_scanner_advanced.py --help

for the full, generated help. Key option categories are summarized below.

5.1 Region and Keywords
	•	-r, --region
Region appended to each keyword query.
Example: "Washington State", "Seattle WA".
	•	-k, --keyword (repeatable)
Search keyword. Multiple -k flags are allowed.
Example: -k daycare -k "child care".
	•	--keywords-file
File containing one keyword per line.
Combined with any --keyword flags.

If neither --keyword nor --keywords-file is provided, built-in SEARCH_KEYWORDS are used.

5.2 Output and Evidence Directories
	•	--output-dir
Directory for JSON, NDJSON, CSV outputs.
Default: output.
	•	--evidence-dir
Directory for evidence NDJSON.
Default: evidence.

5.3 Timing, Throttling, and Limits
	•	--api-sleep
Delay between Google API calls (seconds).
Default: 0.2.
	•	--review-recent-days
Days considered “recent” for Google reviews.
Default: 365.
	•	--http-timeout
Website request timeout in seconds.
Default: 10.
	•	--max-google-results-per-keyword
Optional cap on number of Google Places results per keyword.

5.4 Logging
	•	--log-level
One of DEBUG, INFO, WARNING, ERROR.
Default: INFO.

5.5 Feature Toggles
	•	--no-ads
Disable ad-platform discovery (currently scaffold).
	•	--no-other-listings
Disable discovery from other listing sites (currently scaffold).
	•	--no-website
Disable website fetch and analysis.
	•	--no-social
Disable social profile lookup (placeholder).
	•	--no-gov
Disable WA government / licensing lookups (placeholder).

5.6 Modes
	•	--dry-run
Discovery and dedup only; skip enrichment, scoring, evidence.
Writes providers_discovered.ndjson.
	•	--print-summary-only
Print classification and risk tier summary to stdout.
Files are still written.

5.7 High-Risk Outputs and Filters
	•	--print-top-n
If > 0, prints top N providers by fraud score.
	•	--min-fraud-score
If set, write providers_high_risk.ndjson with providers whose fraud_score is at or above this threshold.
	•	--risk-tier-include (repeatable)
Filter providers_high_risk.ndjson to specific risk tiers.
Allowed values: critical, high, medium, low, unknown.

Examples:

--min-fraud-score 3.0 \
--risk-tier-include critical --risk-tier-include high

5.8 Redaction and CSV
	•	--redact-pii
Redacts PII-like fields (address, phone, email, website, coordinates, evidence excerpts) in output JSON/NDJSON.
	•	--no-csv-summary
Disable writing providers_summary.csv.
	•	--status-include (repeatable)
Restrict NDJSON/CSV outputs to specific statuses.
Allowed values:
	•	licensed_and_active
	•	licensed_but_not_listed
	•	unlicensed_but_listed
	•	unknown

5.9 Run Labeling
	•	--scenario-name
Free-form label for the run, logged for context.
	•	--notes
Short note string attached in logs (not used by scoring).

6. MongoDB / MongoDB Atlas Integration

MongoDB is optional and is enabled only if you pass --mongo-enable and have pymongo installed.

6.1 Basic Enablement

Example:

python daycare_fraud_scanner_advanced.py \
  --region "Washington State" \
  --mongo-enable \
  --mongo-uri "mongodb://localhost:27017" \
  --mongo-db "daycare_fraud_scanner"

6.2 Key Mongo CLI Options
	•	--mongo-enable
Enable Mongo integration.
	•	--mongo-uri
Mongo connection URI. Overrides DCS_MONGO_URI.
	•	--mongo-db
Database name. Overrides DCS_MONGO_DB.
	•	--mongo-providers-collection
Providers collection name.
	•	--mongo-evidence-collection
Evidence collection name.
	•	--mongo-runs-collection
Runs metadata collection name.
	•	--mongo-write-mode
One of:
	•	insert
	•	upsert (default)
	•	replace
	•	--mongo-tag
Optional tag attached to all docs for this run.
	•	--mongo-batch-size
Batch size for bulk writes.
	•	--mongo-dry-run
Connect and validate Mongo connection, but do not write documents.

6.3 Collections and Documents

If enabled, the script writes:
	•	Providers into MONGO_PROVIDERS_COLLECTION (default providers).
	•	Evidence items into MONGO_EVIDENCE_COLLECTION (default evidence).
	•	Run metadata into MONGO_RUNS_COLLECTION (default runs).

Each document includes:
	•	_run_id and run_id for traceability.
	•	_schema_version for schema management.
	•	Optional _tag field for scenario tagging.
	•	Optional _deleted for soft-deletion when enabled.

7. JSON Schema Emission

You can emit JSON Schemas for MongoDB/Atlas validation:
	•	--emit-json-schemas
Generate JSON Schema files after the scan.
	•	--json-schema-dir
Directory to write schema files into.
Default: <output-dir>/schemas.

The following files are created:
	•	providers.schema.json
	•	evidence.schema.json
	•	runs.schema.json

These are draft-07 style schemas suitable as MongoDB collection validators or for external tooling.

Example:

python daycare_fraud_scanner_advanced.py \
  --region "Washington State" \
  --emit-json-schemas \
  --json-schema-dir ./schemas

8. Outputs and File Formats

Assuming --output-dir out and --evidence-dir evidence, typical outputs are:

8.1 Grouped JSON
	•	licensed_but_not_listed.json
	•	licensed_and_active.json
	•	unlicensed_but_listed.json
	•	unknown.json

Each has the structure:

{
  "meta": {
    "run_id": "...",
    "run_timestamp_utc": "...",
    "search_region": "...",
    "search_keywords": [...]
  },
  "providers_by_region": {
    "STATE": {
      "County": {
        "City": [
          { "provider": "object" },
          ...
        ]
      }
    }
  }
}

8.2 Providers NDJSON
	•	providers_all.ndjson
One provider JSON per line. Includes _meta run metadata.
	•	Optional:
	•	providers_high_risk.ndjson
Only written if --min-fraud-score or --risk-tier-include is set and at least one provider matches.

8.3 CSV Summary
	•	providers_summary.csv (unless --no-csv-summary is set)

Columns include:
	•	id
	•	normalized_name
	•	city
	•	county
	•	state
	•	status
	•	risk_tier
	•	fraud_score
	•	legitimacy_score
	•	google_rating
	•	google_user_ratings_total
	•	has_dcyf_license
	•	dcyf_active
	•	has_secretary_of_state_registration
	•	sos_active
	•	has_dol_business_license
	•	dol_active
	•	is_city_low_activity_outlier
	•	is_city_high_activity_outlier
	•	shared_address_count

8.4 Evidence NDJSON
	•	evidence/evidence.ndjson

Each line is an EvidenceItem:
	•	id
	•	provider_id
	•	source_type
	•	label
	•	severity
	•	timestamp_utc
	•	description
	•	url (optional)
	•	raw_excerpt (optional; redacted if --redact-pii)
	•	metadata (structured details)

9. Operational and Ethical Notes
	•	This tool is not a replacement for:
	•	Licensing processes.
	•	Formal investigations.
	•	Due-process mechanisms.
	•	Outputs should be treated as:
	•	Screening indicators.
	•	Leads for human review.
	•	Inputs into a documented investigative workflow.

Before using in any production or case-related context:
	1.	Review CODE_OF_CONDUCT.md and any associated governance documents.
	2.	Ensure your usage is:
	•	Lawful for your jurisdiction.
	•	Approved by relevant oversight bodies.
	•	Documented in internal policies.
	3.	Avoid:
	•	Public posting of raw outputs.
	•	Doxxing or naming-and-shaming behavior.
	•	Automated adverse actions without human review.

10. Quick Start Checklist
	1.	Install dependencies:

pip install requests googlemaps beautifulsoup4 pymongo

	2.	Set your Google Maps API key:

export GOOGLE_MAPS_API_KEY="YOUR_REAL_API_KEY"

	3.	(Optional) Prepare MongoDB and connection string, if you want persistence.
	4.	Run a small test:

python daycare_fraud_scanner_advanced.py \
  --region "Seattle WA" \
  -k daycare \
  --print-summary-only \
  --print-top-n 10


	5.	Review outputs in output/ and evidence/.
	6.	Only after confirming behavior and reviewing governance requirements should you scale up usage or integrate into workflows.
