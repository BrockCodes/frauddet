"""
daycare_fraud_scanner_advanced.py

Comprehensive automation and evidence-collection scaffold for detecting
suspected fraudulent daycare / childcare providers.
# SPDX-License-Identifier: LicenseRef-Leonard-Gov-Investigative-1.0
# SPDX-FileCopyrightText: 2026 Garrett Leonard

Core capabilities:
- Discover providers from:
    - Google Maps / Places (implemented)
    - Ads platforms (scaffold)
    - Other listing/search engines (scaffold)
    - Direct domain/website discovery (scaffold)

- Enrich providers with:
    - Google Place Details (county, status, reviews, last activity)
    - Social presence (scaffold)
    - WA government records (DCYF childcare licenses, SoS, DoR/DoL – scaffold)
    - Website content snapshots (scaffold)

- Classify providers into:
    - Licensed but not listed (Fraud)
    - Licensed, listed, and active (Legit)
    - Unlicensed but listed (Fraud)
    - Unknown (needs review)

- Compute:
    - Fraud score (how suspicious)
    - Legitimacy score (how solid/real it looks)
    - Peer-relative activity signals (city-level outliers)
    - Risk tier

- Output:
    - JSON grouped by state / county / city per result type (with run metadata)
    - NDJSON line-per-provider (“raw dump” for forensic tools)
    - Evidence NDJSON with detailed evidence items
    - Optional CSV summary of providers (non-PII-focused)
    - Optional NDJSON of only “high-risk” providers (filters)

CLI examples:
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
"""

import os
import time
import enum
import logging
import json
import re
import csv
import argparse
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime, timezone
from uuid import uuid4

pip install requestspip install requestsimport requests

try:
    import googlemaps
except ImportError:
    googlemaps = None

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None


# =========================
# Config / Constants
# =========================

GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY", "YOUR_GOOGLE_MAPS_API_KEY")

SEARCH_REGION = os.getenv("DCS_SEARCH_REGION", "Washington State")
SEARCH_KEYWORDS = [
    "daycare",
    "childcare",
    "child care",
    "preschool",
    "early learning center",
]

# Throttle / rate-limiting
API_SLEEP_SECONDS = 0.2

OUTPUT_DIR = "output"          # directory to write JSON files into
EVIDENCE_DIR = "evidence"      # directory to save detailed evidence snapshots
GOOGLE_REVIEW_RECENT_DAYS = 365

# Website crawling
HTTP_TIMEOUT = 10
USER_AGENT = "DaycareFraudScanner/1.1 (+forensic use, not resale)"

# Feature toggles (CLI can override)
ENABLE_ADS_DISCOVERY = True
ENABLE_OTHER_LISTINGS_DISCOVERY = True
ENABLE_WEBSITE_FETCH = True
ENABLE_SOCIAL_LOOKUP = True
ENABLE_GOV_LOOKUP = True
MAX_GOOGLE_RESULTS_PER_KEYWORD: Optional[int] = None

# Output / post-processing features (CLI can override)
REDACT_PII: bool = False
WRITE_CSV_SUMMARY: bool = True
MIN_FRAUD_SCORE_FOR_HIGHRISK_OUTPUT: Optional[float] = None
RISK_TIERS_FOR_HIGHRISK_OUTPUT: List[str] = []
PRINT_TOP_N: int = 0

# Run metadata
RUN_ID = str(uuid4())
RUN_TIMESTAMP_UTC = datetime.now(timezone.utc).isoformat()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


# =========================
# Enumerations
# =========================

class ProviderStatus(enum.Enum):
    LICENSED_AND_ACTIVE = "licensed_and_active"         # legitimate
    LICENSED_BUT_NOT_LISTED = "licensed_but_not_listed" # fraud (your taxonomy)
    UNLICENSED_BUT_LISTED = "unlicensed_but_listed"     # fraud
    UNKNOWN = "unknown"


class RiskTier(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class SourceType(enum.Enum):
    GOOGLE_PLACES = "google_places"
    ADS = "ad_platform"
    OTHER_LISTING = "other_listing"
    MANUAL = "manual"
    WEBSITE = "website"
    DCYF = "dcyf"
    SOS = "secretary_of_state"
    DOL = "department_of_labor"
    SOCIAL = "social"


class EvidenceSeverity(enum.Enum):
    INFO = "info"
    POSITIVE = "positive"      # supports legitimacy
    NEGATIVE = "negative"      # supports fraud suspicion


# =========================
# Evidence Models
# =========================

@dataclass
class EvidenceItem:
    """
    A single piece of evidentiary data collected about a provider.
    This is what a forensic investigator can drill into.
    """
    id: str
    provider_id: str
    source_type: str
    label: str
    severity: str
    timestamp_utc: str
    description: str
    url: Optional[str] = None
    raw_excerpt: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InvestigationTrail:
    """
    Log of how we investigated a given provider.
    """
    steps: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)


# =========================
# Signal & Provider Models
# =========================

@dataclass
class ProviderSignals:
    """
    Signals/features from each surface (ads, social, filings, etc.).
    Designed to be ML-ready, but readable for humans.
    """

    # Web / ads / listings
    discovered_via: List[str] = field(default_factory=list)
    has_google_listing: bool = False
    has_other_ads: bool = False
    has_other_listings: bool = False

    google_place_id: Optional[str] = None
    google_rating: Optional[float] = None
    google_user_ratings_total: Optional[int] = None
    google_reviews_recent: bool = False

    # Google extra detail signals
    google_business_status: Optional[str] = None  # e.g. OPERATIONAL, CLOSED_TEMPORARILY
    google_open_now: Optional[bool] = None
    google_last_review_time: Optional[str] = None        # ISO string
    google_last_review_recency_days: Optional[float] = None

    # Social
    has_facebook_page: bool = False
    has_x_profile: bool = False
    has_linkedin_company: bool = False
    social_recent_activity: bool = False

    # Business / licensing (WA)
    has_secretary_of_state_registration: bool = False
    sos_entity_name: Optional[str] = None
    sos_active: bool = False

    has_dol_business_license: bool = False
    dol_license_number: Optional[str] = None
    dol_active: bool = False

    has_dcyf_license: bool = False
    dcyf_license_number: Optional[str] = None
    dcyf_active: bool = False
    name_mismatch_with_license: bool = False  # scaffold for future matching logic

    # Website content
    website_reachable: bool = False
    website_http_status: Optional[int] = None
    website_title: Optional[str] = None
    website_meta_description: Optional[str] = None
    website_has_license_language: bool = False
    website_has_dcyf_language: bool = False
    website_has_contact_page: bool = False
    website_has_photos_keywords: bool = False
    website_has_staff_bios_keywords: bool = False
    website_last_crawled_utc: Optional[str] = None

    # Physical traffic / map activity
    has_geocoded_location: bool = False
    visitor_activity_likely: bool = False  # derived from maps / reviews / patterns

    # Aggregate / peer comparison
    city_review_volume_rank: Optional[int] = None
    city_review_volume_percentile: Optional[float] = None
    is_city_low_activity_outlier: bool = False
    is_city_high_activity_outlier: bool = False

    # Name / branding signals
    name_generic_score: float = 0.0
    name_contains_location_term: bool = False
    name_contains_personal_name: bool = False

    # Contact / channel richness
    email_domain_type: Optional[str] = None  # "free", "custom", "unknown"

    # Cross-entity pattern flags
    shared_address_count: Optional[int] = None
    shared_phone_count: Optional[int] = None

    # Quantitative scoring
    fraud_score: float = 0.0
    legitimacy_score: float = 0.0


@dataclass
class Provider:
    """
    A normalized representation of a childcare provider across sources.
    """

    id: str
    normalized_name: str

    # Identity / contact
    raw_names: List[str] = field(default_factory=list)
    address: Optional[str] = None
    city: Optional[str] = None
    county: Optional[str] = None
    state: Optional[str] = "WA"
    postal_code: Optional[str] = None
    phone: Optional[str] = None
    website: Optional[str] = None
    primary_email: Optional[str] = None

    latitude: Optional[float] = None
    longitude: Optional[float] = None

    # Signals and classification
    signals: ProviderSignals = field(default_factory=ProviderSignals)
    status: ProviderStatus = ProviderStatus.UNKNOWN
    risk_tier: Optional[str] = None
    debug_reasons: List[str] = field(default_factory=list)

    # Investigation and manual annotation
    investigation: InvestigationTrail = field(default_factory=InvestigationTrail)
    manual_label: Optional[str] = None          # e.g. "confirmed_fraud", "confirmed_legit"
    manual_notes: Optional[str] = None


# =========================
# Utility Functions
# =========================

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "aol.com", "msn.com", "icloud.com", "proton.me",
}

GENERIC_NAME_TERMS = [
    "kids", "kid", "child", "children", "childcare", "child care",
    "daycare", "day care", "tots", "toddler", "toddler care",
    "preschool", "pre-school", "academy", "learning", "learning center",
    "early learning", "early education", "montessori", "school", "center",
    "care", "family", "in-home", "home daycare",
]

LOCATION_TERMS = [
    "washington", "wa", "seattle", "tacoma", "spokane", "everett",
    "bellevue", "olympia", "kent", "yakima", "vancouver",
    "north", "south", "east", "west",
]

PERSONAL_NAME_HINTS = [
    "ms.", "mrs.", "mr.", "miss", "teacher", "aunt", "uncle",
]

def normalize_name(name: str) -> str:
    """
    Basic heuristic normalization for cross-matching names across systems.
    Remove common suffixes, lowercase, squeeze spaces.
    """
    if not name:
        return ""
    name = name.lower().strip()
    for suffix in [" llc", " inc", " inc.", " llc.", " pllc", " pllc.",
                   " corporation", " corp", " corp.", " co.", " company"]:
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return " ".join(name.split())


def sleep_throttle():
    time.sleep(API_SLEEP_SECONDS)


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_address_components_from_str(address: Optional[str]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Best-effort parsing of 'formatted_address' from Google into (city, state, postal)
    if we only have the string.
    """
    city = state = postal = None
    if not address:
        return city, state, postal

    parts = [p.strip() for p in address.split(",")]
    if len(parts) >= 3:
        # Typical pattern: "123 Main St, Seattle, WA 98101, USA"
        city = parts[-3]
        state_zip = parts[-2]
        sz_tokens = state_zip.split()
        if len(sz_tokens) >= 1:
            state = sz_tokens[0]
        if len(sz_tokens) >= 2:
            postal = sz_tokens[1]
    elif len(parts) == 2:
        # Pattern: "Seattle, WA 98101"
        city = parts[0]
        sz_tokens = parts[1].split()
        if len(sz_tokens) >= 1:
            state = sz_tokens[0]
        if len(sz_tokens) >= 2:
            postal = sz_tokens[1]

    return city, state, postal


def extract_components_from_address_components(ac: List[Dict]) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Extract (city, county, state, postal_code) from Google address_components.
    """
    city = county = state = postal = None

    for comp in ac:
        types = comp.get("types", [])
        long_name = comp.get("long_name")
        short_name = comp.get("short_name")

        if "locality" in types or "postal_town" in types:
            city = long_name
        elif "administrative_area_level_2" in types:
            county = long_name
        elif "administrative_area_level_1" in types:
            state = short_name or long_name
        elif "postal_code" in types:
            postal = long_name

    return city, county, state, postal


def get_run_metadata() -> Dict[str, Any]:
    return {
        "run_id": RUN_ID,
        "run_timestamp_utc": RUN_TIMESTAMP_UTC,
        "search_region": SEARCH_REGION,
        "search_keywords": SEARCH_KEYWORDS,
    }


# =========================
# Evidence Handling
# =========================

EVIDENCE_REGISTRY: Dict[str, EvidenceItem] = {}

def add_evidence(provider: Provider,
                 source_type: SourceType,
                 label: str,
                 severity: EvidenceSeverity,
                 description: str,
                 url: Optional[str] = None,
                 raw_excerpt: Optional[str] = None,
                 metadata: Optional[Dict[str, Any]] = None) -> str:
    """
    Add an evidence item to the global registry and link it to a provider.
    """
    evidence_id = str(uuid4())
    item = EvidenceItem(
        id=evidence_id,
        provider_id=provider.id,
        source_type=source_type.value,
        label=label,
        severity=severity.value,
        timestamp_utc=now_utc_iso(),
        description=description,
        url=url,
        raw_excerpt=raw_excerpt,
        metadata=metadata or {}
    )
    EVIDENCE_REGISTRY[evidence_id] = item
    provider.investigation.evidence_ids.append(evidence_id)
    return evidence_id


def serialize_evidence(ev: EvidenceItem, redact: bool) -> Dict[str, Any]:
    """
    Convert EvidenceItem to dict, optionally redacting potentially sensitive fields.
    """
    data = asdict(ev)
    if not redact:
        return data

    # Redact raw_excerpt; optionally also URL if you want to avoid leaking domains
    if data.get("raw_excerpt"):
        data["raw_excerpt"] = "[REDACTED_EXCERPT]"
    # Leave description/metadata so the investigative value remains
    return data


def save_evidence_registry():
    """
    Save the global evidence registry to disk as NDJSON for forensic use.
    """
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    path = os.path.join(EVIDENCE_DIR, "evidence.ndjson")
    with open(path, "w", encoding="utf-8") as f:
        for ev in EVIDENCE_REGISTRY.values():
            f.write(json.dumps(serialize_evidence(ev, REDACT_PII), default=str) + "\n")
    logging.info("Saved %d evidence items to %s", len(EVIDENCE_REGISTRY), path)


# =========================
# Google Maps / Places Integration
# =========================

_gmaps_client = None

def get_gmaps_client():
    global _gmaps_client
    if _gmaps_client is None and googlemaps is not None:
        _gmaps_client = googlemaps.Client(key=GOOGLE_MAPS_API_KEY)
    return _gmaps_client


def search_google_places(keyword: str, region: str) -> List[Dict]:
    client = get_gmaps_client()
    if not client:
        logging.warning("googlemaps library not installed or client not initialized, skipping Google search.")
        return []

    query = f"{keyword} {region}"
    results = []
    page_token = None

    while True:
        params = {"query": query}
        if page_token:
            params["page_token"] = page_token

        logging.info("Querying Google Places for '%s'", query)
        resp = client.places(**params)
        sleep_throttle()

        results.extend(resp.get("results", []))
        page_token = resp.get("next_page_token")
        if not page_token:
            break
        time.sleep(2)  # Google requires small delay before using next_page_token

    logging.info("Google Places returned %d results for query '%s'", len(results), query)
    return results


def extract_providers_from_google(places_results: List[Dict]) -> List[Provider]:
    providers: List[Provider] = []
    for p in places_results:
        name = p.get("name", "")
        normalized = normalize_name(name)
        address = p.get("formatted_address")
        city, state, postal = parse_address_components_from_str(address)
        place_id = p.get("place_id")
        rating = p.get("rating")
        user_ratings_total = p.get("user_ratings_total", 0)

        loc = p.get("geometry", {}).get("location") or {}
        lat = loc.get("lat")
        lng = loc.get("lng")

        provider = Provider(
            id=str(uuid4()),
            normalized_name=normalized,
            raw_names=[name],
            address=address,
            city=city,
            state=state or "WA",
            postal_code=postal,
            latitude=lat,
            longitude=lng,
            signals=ProviderSignals(
                discovered_via=[SourceType.GOOGLE_PLACES.value],
                has_google_listing=True,
                google_place_id=place_id,
                google_rating=rating,
                google_user_ratings_total=user_ratings_total,
                google_reviews_recent=_has_recent_reviews_basic(p),
                has_geocoded_location=bool(loc)
            )
        )
        providers.append(provider)

    return providers


def _has_recent_reviews_basic(place_result: Dict, min_reviews: int = 3) -> bool:
    user_ratings_total = place_result.get("user_ratings_total", 0)
    return user_ratings_total >= min_reviews


def enrich_provider_with_google_details(provider: Provider):
    """
    Use Place Details to enrich provider with:
    - more accurate address, city, state, postal, county
    - business status
    - open_now
    - last review timestamp / recency
    - rating and user_ratings_total
    """
    client = get_gmaps_client()
    if not client:
        provider.investigation.errors.append("Google client not available for details.")
        return

    place_id = provider.signals.google_place_id
    if not place_id:
        return

    provider.investigation.steps.append("google_details")

    try:
        fields = [
            "formatted_address",
            "address_component",
            "opening_hours",
            "business_status",
            "rating",
            "user_ratings_total",
            "review",
            "geometry",
            "formatted_phone_number",
            "website",
        ]
        resp = client.place(place_id=place_id, fields=fields)
        sleep_throttle()
    except Exception as e:
        msg = f"Failed to fetch place details: {e}"
        logging.warning("%s for %s", msg, provider.normalized_name)
        provider.investigation.errors.append(msg)
        return

    result = resp.get("result", {})
    if not result:
        return

    # Address / city / county / state / postal
    formatted_address = result.get("formatted_address") or provider.address
    provider.address = formatted_address
    ac = result.get("address_components")
    if ac:
        city, county, state, postal = extract_components_from_address_components(ac)
        if city:
            provider.city = city
        if county:
            provider.county = county
        if state:
            provider.state = state
        if postal:
            provider.postal_code = postal

    # Lat/Lng
    loc = result.get("geometry", {}).get("location") or {}
    if loc:
        provider.latitude = loc.get("lat", provider.latitude)
        provider.longitude = loc.get("lng", provider.longitude)
        provider.signals.has_geocoded_location = True

    # Phone and website
    phone = result.get("formatted_phone_number")
    if phone:
        provider.phone = phone
    website = result.get("website")
    if website:
        provider.website = website

    # Rating and review volume
    rating = result.get("rating")
    if rating is not None:
        provider.signals.google_rating = rating
    user_ratings_total = result.get("user_ratings_total")
    if user_ratings_total is not None:
        provider.signals.google_user_ratings_total = user_ratings_total

    # Business status
    business_status = result.get("business_status")
    provider.signals.google_business_status = business_status

    # Opening hours
    opening_hours = result.get("opening_hours") or {}
    if isinstance(opening_hours, dict):
        provider.signals.google_open_now = opening_hours.get("open_now")

    # Reviews – use newest review's timestamp as "last activity"
    reviews = result.get("reviews") or []
    if reviews:
        newest_review = max(
            reviews,
            key=lambda r: r.get("time", 0)
        )
        t = newest_review.get("time")
        if t:
            dt = datetime.fromtimestamp(t, tz=timezone.utc)
            now = datetime.now(timezone.utc)
            delta_days = (now - dt).total_seconds() / 86400.0
            provider.signals.google_last_review_time = dt.isoformat()
            provider.signals.google_last_review_recency_days = delta_days
            provider.signals.google_reviews_recent = delta_days <= GOOGLE_REVIEW_RECENT_DAYS
            provider.signals.visitor_activity_likely = provider.signals.google_reviews_recent

            add_evidence(
                provider,
                SourceType.GOOGLE_PLACES,
                label="recent_google_review",
                severity=EvidenceSeverity.POSITIVE,
                description=f"Most recent Google review {delta_days:.1f} days ago.",
                metadata={"delta_days": delta_days}
            )
        else:
            provider.signals.visitor_activity_likely = (
                (provider.signals.google_user_ratings_total or 0) >= 10
            )
    else:
        provider.signals.visitor_activity_likely = (
            (provider.signals.google_user_ratings_total or 0) >= 10
        )

    # Evidence example: Google listing exists
    add_evidence(
        provider,
        SourceType.GOOGLE_PLACES,
        label="google_listing",
        severity=EvidenceSeverity.POSITIVE,
        description="Google Places listing present.",
        url=f"https://maps.google.com/?q=place_id:{place_id}"
    )


# =========================
# Ads & Other Listing Crawlers (Scaffold)
# =========================

def crawl_ad_platforms_for_providers() -> List[Provider]:
    """
    Scaffold for:
      - Google Ads
      - Bing Ads
      - Other paid placements

    Return a list of Provider objects discovered ONLY through ad data.
    Currently returns empty and is intended for future build-out.
    """
    logging.info("crawl_ad_platforms_for_providers: not implemented; returning empty list.")
    return []


def crawl_other_listing_sites_for_providers() -> List[Provider]:
    """
    Scaffold for:
      - Yelp
      - Yellow Pages
      - Other childcare directories
    """
    logging.info("crawl_other_listing_sites_for_providers: not implemented; returning empty list.")
    return []


# =========================
# Website Crawler (Scaffold but functional)
# =========================

EMAIL_REGEX = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)

def classify_email_domain(email: str) -> str:
    """
    Classify email domain as 'free', 'custom', or 'unknown'.
    """
    if not email or "@" not in email:
        return "unknown"
    domain = email.split("@")[-1].lower().strip()
    if domain in FREE_EMAIL_DOMAINS:
        return "free"
    if "." in domain:
        return "custom"
    return "unknown"


def compute_website_content_flags(text: str) -> Dict[str, bool]:
    """
    Lightweight keyword-based content flags for website text.
    """
    t = text.lower()
    has_contact = any(k in t for k in ["contact us", "contact", "schedule a tour", "visit us"])
    has_photos = any(k in t for k in ["photo gallery", "photos", "our classrooms", "our facility"])
    has_staff_bios = any(k in t for k in ["our teachers", "meet our staff", "our team", "teacher bios"])
    return {
        "website_has_contact_page": has_contact,
        "website_has_photos_keywords": has_photos,
        "website_has_staff_bios_keywords": has_staff_bios,
    }


def fetch_website(provider: Provider):
    """
    Fetch provider website (if any), record basic metadata and possible license language.
    This is powerful for both vindicating and validating fraud/suspicion.
    """
    if not provider.website:
        return

    provider.investigation.steps.append("website_fetch")

    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.get(provider.website, headers=headers, timeout=HTTP_TIMEOUT)
    except Exception as e:
        msg = f"Website request error: {e}"
        logging.warning("%s for %s", msg, provider.website)
        provider.investigation.errors.append(msg)
        return

    provider.signals.website_http_status = resp.status_code
    provider.signals.website_reachable = resp.ok
    provider.signals.website_last_crawled_utc = now_utc_iso()

    raw_excerpt = resp.text[:2000]  # keep small sample for evidence, not entire page
    add_evidence(
        provider,
        SourceType.WEBSITE,
        label="website_fetch",
        severity=EvidenceSeverity.INFO,
        description=f"Fetched website with status {resp.status_code}.",
        url=provider.website,
        raw_excerpt=raw_excerpt
    )

    if not resp.ok:
        return

    text = resp.text

    # Extract primary email if present
    emails = EMAIL_REGEX.findall(text)
    if emails:
        provider.primary_email = emails[0].strip()
        provider.signals.email_domain_type = classify_email_domain(provider.primary_email)
        add_evidence(
            provider,
            SourceType.WEBSITE,
            label="email_found",
            severity=EvidenceSeverity.INFO,
            description=f"Primary email extracted: {provider.primary_email}",
            metadata={"email_domain_type": provider.signals.email_domain_type}
        )
    else:
        provider.signals.email_domain_type = "unknown"

    if BeautifulSoup:
        soup = BeautifulSoup(text, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else None
        provider.signals.website_title = title

        # Metadata
        desc_tag = soup.find("meta", attrs={"name": "description"})
        if desc_tag and desc_tag.get("content"):
            provider.signals.website_meta_description = desc_tag["content"].strip()

        visible_text = soup.get_text(" ", strip=True).lower()

        # Very simple language checks
        license_keywords = ["licensed", "state licensed", "dcyf", "child care license", "licensed daycare"]
        if any(k in visible_text for k in license_keywords):
            provider.signals.website_has_license_language = True
            add_evidence(
                provider,
                SourceType.WEBSITE,
                label="license_language",
                severity=EvidenceSeverity.POSITIVE,
                description="Website mentions licensing-related language.",
                url=provider.website
            )

        dcyf_keywords = ["dcyf", "department of children, youth, and families"]
        if any(k in visible_text for k in dcyf_keywords):
            provider.signals.website_has_dcyf_language = True

        # Structural content flags
        flags = compute_website_content_flags(visible_text)
        provider.signals.website_has_contact_page = flags["website_has_contact_page"]
        provider.signals.website_has_photos_keywords = flags["website_has_photos_keywords"]
        provider.signals.website_has_staff_bios_keywords = flags["website_has_staff_bios_keywords"]

    else:
        # If BeautifulSoup is not installed, we leave HTML as raw evidence only.
        provider.investigation.errors.append("BeautifulSoup not installed; cannot parse HTML.")


# =========================
# Social (Scaffold)
# =========================

def crawl_social_profiles_for_provider(provider: Provider):
    """
    Scaffold: enrich Provider with social signals:
      - Facebook Graph API
      - X (Twitter) API
      - LinkedIn Company API

    For now, this is a placeholder. Implement according to platform ToS.
    """
    provider.investigation.steps.append("social_lookup")
    logging.info("crawl_social_profiles_for_provider(%s): placeholder", provider.normalized_name)
    # Example future logic:
    #   if fb_page_found and last_post_within_90_days:
    #       provider.signals.has_facebook_page = True
    #       provider.signals.social_recent_activity = True
    pass


# =========================
# WA Government & Licensing (Scaffold)
# =========================

def query_secretary_of_state(normalized_name: str) -> Tuple[bool, bool, Optional[str]]:
    """
    Query WA Secretary of State for an entity name.
    Return (found, active, official_name).

    Implement using WA SoS business search (API or HTML).
    """
    logging.info("query_secretary_of_state(%s): placeholder returning not found", normalized_name)
    return False, False, None


def query_department_of_labor(normalized_name: str) -> Tuple[bool, bool, Optional[str]]:
    """
    Query WA Department of Revenue / Licensing for a business license.
    Return (found, active, license_number).
    """
    logging.info("query_department_of_labor(%s): placeholder returning not found", normalized_name)
    return False, False, None


def query_dcyf_childcare_license(normalized_name: str, city: Optional[str] = None) -> Tuple[bool, bool, Optional[str]]:
    """
    Query WA DCYF public childcare search.
    Return (found, active, license_number).
    """
    logging.info("query_dcyf_childcare_license(%s, city=%s): placeholder returning not found",
                 normalized_name, city)
    return False, False, None


def enrich_with_government_records(provider: Provider):
    """
    Enrich provider.signals with WA licensing / registration data.
    This is where the real DCYF/SoS/DoR calls will live.
    """
    n = provider.normalized_name
    provider.investigation.steps.append("gov_lookup")

    # WA Secretary of State
    sos_found, sos_active, sos_name = query_secretary_of_state(n)
    provider.signals.has_secretary_of_state_registration = sos_found
    provider.signals.sos_active = sos_active
    provider.signals.sos_entity_name = sos_name
    if sos_found:
        add_evidence(
            provider,
            SourceType.SOS,
            label="sos_record",
            severity=EvidenceSeverity.POSITIVE if sos_active else EvidenceSeverity.INFO,
            description=f"Secretary of State record found. Active={sos_active}.",
            metadata={"entity_name": sos_name}
        )

    # Dept. of Labor / Revenue / Business Licensing
    dol_found, dol_active, dol_license = query_department_of_labor(n)
    provider.signals.has_dol_business_license = dol_found
    provider.signals.dol_active = dol_active
    provider.signals.dol_license_number = dol_license
    if dol_found:
        add_evidence(
            provider,
            SourceType.DOL,
            label="dol_license",
            severity=EvidenceSeverity.POSITIVE if dol_active else EvidenceSeverity.INFO,
            description=f"DOL/DoR license found. Active={dol_active}.",
            metadata={"license_number": dol_license}
        )

    # DCYF childcare licensing
    dcyf_found, dcyf_active, dcyf_license = query_dcyf_childcare_license(n, provider.city)
    provider.signals.has_dcyf_license = dcyf_found
    provider.signals.dcyf_active = dcyf_active
    provider.signals.dcyf_license_number = dcyf_license
    if dcyf_found:
        add_evidence(
            provider,
            SourceType.DCYF,
            label="dcyf_license",
            severity=EvidenceSeverity.POSITIVE if dcyf_active else EvidenceSeverity.NEGATIVE,
            description=f"DCYF childcare license found. Active={dcyf_active}.",
            metadata={"license_number": dcyf_license}
        )


# =========================
# Name / Peer / Shared-contact Analysis
# =========================

def compute_name_signals(provider: Provider):
    """
    Compute name-related signals: generic score, location/personal hints.
    """
    name = provider.normalized_name or ""
    tokens = name.split()
    token_count = len(tokens) if tokens else 1

    generic_hits = 0
    location_flag = False
    personal_flag = False

    lower_name = name.lower()
    for term in GENERIC_NAME_TERMS:
        if term in lower_name:
            generic_hits += 1

    for term in LOCATION_TERMS:
        if term in lower_name:
            location_flag = True
            break

    for term in PERSONAL_NAME_HINTS:
        if term in lower_name:
            personal_flag = True
            break

    provider.signals.name_generic_score = float(generic_hits) / float(token_count)
    provider.signals.name_contains_location_term = location_flag
    provider.signals.name_contains_personal_name = personal_flag


def compute_city_stats(providers: List[Provider]) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
    """
    Build city-level statistics (currently only review volume).
    Returns:
        { (state, county, city): { "reviews": [counts...] } }
    """
    stats: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for p in providers:
        state = (p.state or "UNKNOWN").upper()
        county = (p.county or "UNKNOWN").title()
        city = (p.city or "UNKNOWN").title()
        key = (state, county, city)

        reviews = p.signals.google_user_ratings_total or 0
        bucket = stats.setdefault(key, {"reviews": []})
        bucket["reviews"].append(reviews)

    return stats


def enrich_providers_with_city_stats(providers: List[Provider],
                                     city_stats: Dict[Tuple[str, str, str], Dict[str, Any]]):
    """
    For each provider, compute:
      - city_review_volume_rank
      - city_review_volume_percentile
      - outlier flags for low/high activity
    """
    for key, bucket in city_stats.items():
        counts = bucket["reviews"]
        if not counts:
            continue
        sorted_counts = sorted(counts)
        n = len(sorted_counts)
        if n == 1:
            bucket["median"] = sorted_counts[0]
        else:
            mid = n // 2
            if n % 2 == 1:
                bucket["median"] = sorted_counts[mid]
            else:
                bucket["median"] = 0.5 * (sorted_counts[mid - 1] + sorted_counts[mid])

        bucket["min"] = sorted_counts[0]
        bucket["max"] = sorted_counts[-1]

    for p in providers:
        state = (p.state or "UNKNOWN").upper()
        county = (p.county or "UNKNOWN").title()
        city = (p.city or "UNKNOWN").title()
        key = (state, county, city)
        stats = city_stats.get(key)
        if not stats:
            continue

        reviews = p.signals.google_user_ratings_total or 0
        counts = sorted(stats["reviews"])
        n = len(counts)
        if n == 0:
            continue

        # Rank: 1-based index in sorted order
        rank = sum(1 for c in counts if c <= reviews)
        p.signals.city_review_volume_rank = rank
        # Percentile: simple rank-based
        if n > 1:
            percentile = (rank - 1) / (n - 1)
        else:
            percentile = 1.0
        p.signals.city_review_volume_percentile = percentile

        median = stats.get("median", 0)
        # Very low activity compared to peers with significant volume
        if median > 5 and reviews == 0:
            p.signals.is_city_low_activity_outlier = True
        if percentile is not None and percentile > 0.9 and reviews >= median and median > 0:
            p.signals.is_city_high_activity_outlier = True

        # Evidence for outliers
        if p.signals.is_city_low_activity_outlier:
            add_evidence(
                p,
                SourceType.GOOGLE_PLACES,
                label="low_activity_outlier",
                severity=EvidenceSeverity.NEGATIVE,
                description="Provider has zero reviews in a city where peers show significant review activity.",
                metadata={"city_median_reviews": median, "provider_reviews": reviews}
            )
        if p.signals.is_city_high_activity_outlier:
            add_evidence(
                p,
                SourceType.GOOGLE_PLACES,
                label="high_activity_outlier",
                severity=EvidenceSeverity.INFO,
                description="Provider has unusually high review volume compared to city peers.",
                metadata={"city_median_reviews": median, "provider_reviews": reviews}
            )


def compute_shared_contact_stats(providers: List[Provider]):
    """
    Compute how many providers share the same address and phone.
    """
    addr_map: Dict[str, int] = {}
    phone_map: Dict[str, int] = {}

    for p in providers:
        if p.address:
            addr_norm = p.address.strip().lower()
            addr_map[addr_norm] = addr_map.get(addr_norm, 0) + 1
        if p.phone:
            phone_norm = p.phone.strip()
            phone_map[phone_norm] = phone_map.get(phone_norm, 0) + 1

    for p in providers:
        if p.address:
            addr_norm = p.address.strip().lower()
            p.signals.shared_address_count = addr_map.get(addr_norm, 1)
        else:
            p.signals.shared_address_count = None

        if p.phone:
            phone_norm = p.phone.strip()
            p.signals.shared_phone_count = phone_map.get(phone_norm, 1)
        else:
            p.signals.shared_phone_count = None

        # Evidence for shared contacts
        if p.signals.shared_address_count and p.signals.shared_address_count > 3:
            add_evidence(
                p,
                SourceType.GOOGLE_PLACES,
                label="shared_address_multi_provider",
                severity=EvidenceSeverity.NEGATIVE,
                description=f"Address appears to host {p.signals.shared_address_count} childcare providers.",
                metadata={"shared_address_count": p.signals.shared_address_count}
            )


# =========================
# Classification & Scoring
# =========================

def compute_fraud_score(provider: Provider) -> float:
    """
    Simple heuristic fraud score. Higher = more suspicious.
    """
    s = provider.signals
    score = 0.0

    licensed = s.has_dcyf_license and s.dcyf_active
    listed = s.has_google_listing or s.has_facebook_page or s.has_x_profile or s.has_linkedin_company

    # Core structural mismatches
    if licensed and not listed:
        score += 3.0  # licensed but invisible
    if (not licensed) and listed:
        score += 3.0  # visible but not licensed

    # No SoS or DOL record
    if not s.has_secretary_of_state_registration:
        score += 0.5
    if not s.has_dol_business_license:
        score += 0.5

    # Business status flags from Google
    if s.google_business_status and "CLOSED" in s.google_business_status.upper():
        score += 1.0

    # Very small or stale presence
    if listed and not s.google_reviews_recent and (s.google_user_ratings_total or 0) > 0:
        score += 0.5

    # No activity signals at all, yet appears as open provider
    if listed and not (s.google_reviews_recent or s.social_recent_activity or s.visitor_activity_likely):
        score += 0.5

    # Website contradictory signals (present but no mention of credentials, etc.)
    if s.website_reachable and not (s.website_has_license_language or s.website_has_dcyf_language) and licensed:
        score += 0.5

    # City-level low-activity outlier
    if s.is_city_low_activity_outlier and listed:
        score += 0.5

    # Shared address with many providers
    if s.shared_address_count and s.shared_address_count > 3:
        score += 0.5

    # Free email domain while advertising, no license
    if s.email_domain_type == "free" and listed and not licensed:
        score += 0.25

    # Very generic name with no strong legitimacy signals
    if s.name_generic_score >= 1.0 and not licensed:
        score += 0.25

    return score


def compute_legitimacy_score(provider: Provider) -> float:
    """
    Positive score indicating how legitimate / real the provider appears.
    """
    s = provider.signals
    score = 0.0

    # License / registration signals
    if s.has_dcyf_license and s.dcyf_active:
        score += 4.0
    if s.has_secretary_of_state_registration and s.sos_active:
        score += 1.0
    if s.has_dol_business_license and s.dol_active:
        score += 1.0

    # Activity / presence
    if s.has_google_listing:
        score += 0.5
    if s.google_reviews_recent:
        score += 1.0
    if s.visitor_activity_likely:
        score += 0.5
    if s.social_recent_activity:
        score += 0.5

    # Website signals
    if s.website_reachable:
        score += 0.5
    if s.website_has_license_language:
        score += 1.0
    if s.website_has_dcyf_language:
        score += 0.5
    if s.website_has_contact_page:
        score += 0.25
    if s.website_has_photos_keywords or s.website_has_staff_bios_keywords:
        score += 0.25

    # Peer-relative review strength
    if s.city_review_volume_percentile is not None and s.city_review_volume_percentile > 0.5:
        score += 0.25

    # Custom email domain plus website is a mild positive
    if s.email_domain_type == "custom" and s.website_reachable:
        score += 0.25

    return score


def assign_risk_tier(provider: Provider):
    """
    Assign a coarse risk tier based on fraud and legitimacy scores + status.
    """
    s = provider.signals
    suspicion_index = s.fraud_score - s.legitimacy_score

    tier = RiskTier.UNKNOWN

    if provider.status == ProviderStatus.UNLICENSED_BUT_LISTED and suspicion_index >= 2.0:
        tier = RiskTier.CRITICAL
    elif provider.status == ProviderStatus.LICENSED_BUT_NOT_LISTED and suspicion_index >= 1.5:
        tier = RiskTier.HIGH
    elif provider.status == ProviderStatus.LICENSED_AND_ACTIVE and suspicion_index <= -2.0:
        tier = RiskTier.LOW
    else:
        # Fallbacks based on suspicion index alone
        if suspicion_index >= 2.5:
            tier = RiskTier.CRITICAL
        elif suspicion_index >= 1.5:
            tier = RiskTier.HIGH
        elif suspicion_index <= -1.0:
            tier = RiskTier.LOW
        else:
            tier = RiskTier.MEDIUM

    provider.risk_tier = tier.value
    provider.debug_reasons.append(f"Risk tier: {provider.risk_tier} (suspicion_index={suspicion_index:.2f})")


def classify_provider(provider: Provider):
    """
    Apply heuristic rules to classify providers and compute scores.
    """
    s = provider.signals
    reasons = []

    licensed = s.has_dcyf_license and s.dcyf_active
    listed = s.has_google_listing or s.has_facebook_page or s.has_x_profile or s.has_linkedin_company
    active_traffic = s.google_reviews_recent or s.social_recent_activity or s.visitor_activity_likely

    if licensed and not listed:
        provider.status = ProviderStatus.LICENSED_BUT_NOT_LISTED
        reasons.append("Has active DCYF license but no visible web/map/social listing.")
    elif licensed and listed and active_traffic:
        provider.status = ProviderStatus.LICENSED_AND_ACTIVE
        reasons.append("Active DCYF license, listings, and signs of visitor/engagement activity.")
    elif (not licensed) and listed:
        provider.status = ProviderStatus.UNLICENSED_BUT_LISTED
        reasons.append("Listed online as daycare but no active DCYF license found.")
    else:
        provider.status = ProviderStatus.UNKNOWN
        reasons.append("Signals inconclusive under current rules.")

    s.fraud_score = compute_fraud_score(provider)
    s.legitimacy_score = compute_legitimacy_score(provider)
    reasons.append(f"Fraud score: {s.fraud_score:.2f}")
    reasons.append(f"Legitimacy score: {s.legitimacy_score:.2f}")

    provider.debug_reasons = reasons
    assign_risk_tier(provider)


def serialize_provider(provider: Provider, redact: bool) -> Dict[str, Any]:
    """
    Convert Provider to dict, optionally redacting PII-leaning fields for sharing.
    Ensures enum fields are normalized to JSON/Mongo-friendly strings.
    """
    data = asdict(provider)

    # Normalize Enum → plain string
    if isinstance(provider.status, enum.Enum):
        data["status"] = provider.status.value

    # Future-proof: normalize any other enum fields safely
    if "risk_tier" in data and isinstance(data["risk_tier"], enum.Enum):
        data["risk_tier"] = data["risk_tier"].value

    if not redact:
        return data

    # Core identity redactions
    for key in ("address", "phone", "website", "primary_email", "latitude", "longitude"):
        if key in data and data[key] is not None:
            data[key] = f"[REDACTED_{key.upper()}]"

    # Redact some signals that may expose IDs or precise contact info
    signals = data.get("signals") or {}
    if "google_place_id" in signals and signals["google_place_id"]:
        signals["google_place_id"] = "[REDACTED_PLACE_ID]"
    if "shared_address_count" in signals and signals["shared_address_count"] is not None:
        # count itself is non-PII; leave as-is
        pass
    data["signals"] = signals

    # Investigation trail might carry raw error messages; leave as-is for now
    return data

def group_providers_by_region(providers: List[Provider]) -> Dict[str, Dict[str, Dict[str, List[Dict]]]]:
    """
    Group providers into a nested mapping:
        { state: { county: { city: [provider_dicts] } } }
    For each city list, providers are sorted by fraud_score descending.
    """
    grouped: Dict[str, Dict[str, Dict[str, List[Dict]]]] = {}

    providers_sorted = sorted(
        providers,
        key=lambda p: p.signals.fraud_score,
        reverse=True
    )

    for p in providers_sorted:
        state = (p.state or "UNKNOWN").upper()
        county = (p.county or "UNKNOWN").title()
        city = (p.city or "UNKNOWN").title()

        grouped.setdefault(state, {}).setdefault(county, {}).setdefault(city, []).append(
            serialize_provider(p, REDACT_PII)
        )

    return grouped


def save_grouped_json(filename: str, providers: List[Provider]):
    """
    Save providers to a JSON file grouped by state/county/city,
    with top-level run metadata.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path = os.path.join(OUTPUT_DIR, filename)
    data = {
        "meta": get_run_metadata(),
        "providers_by_region": group_providers_by_region(providers),
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)

    logging.info("Wrote %d providers to %s", len(providers), path)

def save_providers_ndjson(filename: str, providers: List[Provider]):
    """
    Save providers in NDJSON format.
    If STATUSES_FOR_OUTPUT is non-empty, only include those statuses.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path = os.path.join(OUTPUT_DIR, filename)

    if STATUSES_FOR_OUTPUT:
        providers_iter = [p for p in providers if p.status.value in STATUSES_FOR_OUTPUT]
    else:
        providers_iter = providers

    with open(path, "w", encoding="utf-8") as f:
        for p in providers_iter:
            record = serialize_provider(p, REDACT_PII)
            record["_meta"] = get_run_metadata()
            f.write(json.dumps(record, default=str) + "\n")
    logging.info("Wrote %d providers to NDJSON %s", len(providers_iter), path)


def save_providers_csv(filename: str, providers: List[Provider]):
    """
    Save a non-PII-focused CSV summary for quick triage / spreadsheets.
    Respects STATUSES_FOR_OUTPUT if provided.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path = os.path.join(OUTPUT_DIR, filename)

    if STATUSES_FOR_OUTPUT:
        providers_iter = [p for p in providers if p.status.value in STATUSES_FOR_OUTPUT]
    else:
        providers_iter = providers

    fieldnames = [
        "id",
        "normalized_name",
        "city",
        "county",
        "state",
        "status",
        "risk_tier",
        "fraud_score",
        "legitimacy_score",
        "google_rating",
        "google_user_ratings_total",
        "has_dcyf_license",
        "dcyf_active",
        "has_secretary_of_state_registration",
        "sos_active",
        "has_dol_business_license",
        "dol_active",
        "is_city_low_activity_outlier",
        "is_city_high_activity_outlier",
        "shared_address_count",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for p in providers_iter:
            s = p.signals
            writer.writerow({
                "id": p.id,
                "normalized_name": p.normalized_name,
                "city": p.city,
                "county": p.county,
                "state": p.state,
                "status": p.status.value,
                "risk_tier": p.risk_tier,
                "fraud_score": s.fraud_score,
                "legitimacy_score": s.legitimacy_score,
                "google_rating": s.google_rating,
                "google_user_ratings_total": s.google_user_ratings_total,
                "has_dcyf_license": s.has_dcyf_license,
                "dcyf_active": s.dcyf_active,
                "has_secretary_of_state_registration": s.has_secretary_of_state_registration,
                "sos_active": s.sos_active,
                "has_dol_business_license": s.has_dol_business_license,
                "dol_active": s.dol_active,
                "is_city_low_activity_outlier": s.is_city_low_activity_outlier,
                "is_city_high_activity_outlier": s.is_city_high_activity_outlier,
                "shared_address_count": s.shared_address_count,
            })
    logging.info("Wrote CSV provider summary to %s", path)


# =========================
# Orchestration
# =========================

def deduplicate_providers(providers: List[Provider]) -> List[Provider]:
    """
    Merge providers with same normalized_name and similar address.
    For production, replace this with proper fuzzy matching and address normalization.
    """
    by_name: Dict[str, Provider] = {}
    for p in providers:
        key = p.normalized_name
        existing = by_name.get(key)
        if not existing:
            by_name[key] = p
        else:
            # Merge names
            existing.raw_names.extend(n for n in p.raw_names if n not in existing.raw_names)
            # Keep first address but prefer the more detailed one later if needed
            if not existing.address and p.address:
                existing.address = p.address
            # Merge coordinates and basic signals
            existing.latitude = existing.latitude or p.latitude
            existing.longitude = existing.longitude or p.longitude

            es = existing.signals
            ps = p.signals

            es.discovered_via = list(set(es.discovered_via + ps.discovered_via))
            es.has_google_listing |= ps.has_google_listing
            es.has_other_ads |= ps.has_other_ads
            es.has_other_listings |= ps.has_other_listings

            es.google_user_ratings_total = max(
                es.google_user_ratings_total or 0,
                ps.google_user_ratings_total or 0
            )

    return list(by_name.values())


def _print_top_n_providers(providers: List[Provider], n: int):
    if n <= 0:
        return
    sorted_providers = sorted(
        providers,
        key=lambda p: p.signals.fraud_score,
        reverse=True
    )
    top = sorted_providers[:n]
    print("\n=== Top Suspicious Providers (by fraud_score) ===")
    print(f"{'Fraud':>6} {'Legit':>6} {'Tier':>9}  {'Status':>22}  Name / City")
    print("-" * 80)
    for p in top:
        s = p.signals
        print(f"{s.fraud_score:6.2f} {s.legitimacy_score:6.2f} {str(p.risk_tier or ''):>9}  {p.status.value:>22}  {p.normalized_name} [{p.city or 'N/A'}, {p.state or 'N/A'}]")
    print("===============================================\n")

# =========================
# MongoDB / PyMongo + Schema / Export Helpers
# =========================

# These globals are configurable via env or CLI (see parse_args / main below)
MONGO_ENABLED = False

MONGO_URI = os.getenv("DCS_MONGO_URI", "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("DCS_MONGO_DB", "daycare_fraud_scanner")
MONGO_PROVIDERS_COLLECTION = os.getenv("DCS_MONGO_PROVIDERS_COLL", "providers")
MONGO_EVIDENCE_COLLECTION = os.getenv("DCS_MONGO_EVIDENCE_COLL", "evidence")
MONGO_RUNS_COLLECTION = os.getenv("DCS_MONGO_RUNS_COLL", "runs")

# insert|upsert|replace
MONGO_WRITE_MODE = os.getenv("DCS_MONGO_WRITE_MODE", "upsert")
MONGO_TAG = os.getenv("DCS_MONGO_TAG", None)

# Connection / pool tuning
MONGO_CONNECT_TIMEOUT_MS = int(os.getenv("DCS_MONGO_CONNECT_TIMEOUT_MS", "5000"))
MONGO_SOCKET_TIMEOUT_MS = int(os.getenv("DCS_MONGO_SOCKET_TIMEOUT_MS", "15000"))
MONGO_MAX_POOL_SIZE = int(os.getenv("DCS_MONGO_MAX_POOL_SIZE", "50"))
MONGO_MIN_POOL_SIZE = int(os.getenv("DCS_MONGO_MIN_POOL_SIZE", "0"))
MONGO_RETRY_WRITES = os.getenv("DCS_MONGO_RETRY_WRITES", "true").lower() == "true"
MONGO_COMPRESSORS = os.getenv("DCS_MONGO_COMPRESSORS", "")  # e.g. "snappy,zlib,zstd"

# Read preference: primary|primaryPreferred|secondary|secondaryPreferred|nearest
MONGO_READ_PREFERENCE = os.getenv("DCS_MONGO_READ_PREFERENCE", "primary")

# Write concern: "1", "majority", "0", etc.
MONGO_WRITE_CONCERN = os.getenv("DCS_MONGO_WRITE_CONCERN", "majority")

# TLS / Atlas extras
# For MongoDB Atlas, simply set MONGO_URI to the "mongodb+srv://..." connection string.
MONGO_TLS = os.getenv("DCS_MONGO_TLS", "false").lower() == "true"
MONGO_TLS_CA_FILE = os.getenv("DCS_MONGO_TLS_CA_FILE", None)
MONGO_REPLICA_SET = os.getenv("DCS_MONGO_REPLICA_SET", None)

# Schema / indexing / migration
MONGO_INDEX_BOOTSTRAP = os.getenv("DCS_MONGO_INDEX_BOOTSTRAP", "true").lower() == "true"
MONGO_SCHEMA_VERSION = os.getenv("DCS_MONGO_SCHEMA_VERSION", "1.0.0")
MONGO_ALLOW_SCHEMA_DOWNGRADE = os.getenv("DCS_MONGO_ALLOW_SCHEMA_DOWNGRADE", "false").lower() == "true"

# Batch / dry-run
MONGO_BATCH_SIZE = int(os.getenv("DCS_MONGO_BATCH_SIZE", "500"))
MONGO_DRY_RUN = os.getenv("DCS_MONGO_DRY_RUN", "false").lower() == "true"  # "connect only" mode, no writes

# Optional soft-delete support
MONGO_SOFT_DELETE = os.getenv("DCS_MONGO_SOFT_DELETE", "true").lower() == "true"

# Optional status filter for CSV / NDJSON exports
STATUSES_FOR_OUTPUT: List[str] = []  # populated from CLI --status-include

try:
    from pymongo import MongoClient, errors as pymongo_errors
    from pymongo import ReadPreference, WriteConcern
except ImportError:
    MongoClient = None
    pymongo_errors = None

_mongo_client = None  # type: ignore[assignment]
_mongo_indexes_ensured = False  # guard so we do not recreate indexes every run


def _map_read_preference(name: str):
    """
    Map a string config value to a PyMongo ReadPreference constant.
    """
    name = (name or "").lower()
    mapping = {
        "primary": ReadPreference.PRIMARY,
        "primarypreferred": ReadPreference.PRIMARY_PREFERRED,
        "primary_preferred": ReadPreference.PRIMARY_PREFERRED,
        "secondary": ReadPreference.SECONDARY,
        "secondarypreferred": ReadPreference.SECONDARY_PREFERRED,
        "secondary_preferred": ReadPreference.SECONDARY_PREFERRED,
        "nearest": ReadPreference.NEAREST,
    }
    return mapping.get(name, ReadPreference.PRIMARY)


def _map_write_concern(name: str) -> WriteConcern:
    """
    Map a string config value to a PyMongo WriteConcern instance.
    """
    if not name:
        return WriteConcern("majority")

    lower = name.lower()
    if lower == "majority":
        return WriteConcern("majority")
    try:
        w_int = int(name)
        return WriteConcern(w=w_int)
    except ValueError:
        return WriteConcern(w=name)


def get_mongo_client():
    """
    Lazily instantiate and return a MongoClient if Mongo integration is enabled.
    Works for local MongoDB and MongoDB Atlas (mongodb+srv URIs).
    Returns None if PyMongo is not installed or connection fails.
    """
    global _mongo_client

    if not MONGO_ENABLED:
        return None

    if MongoClient is None:
        logging.error("PyMongo (pymongo) is not installed; MongoDB integration is disabled.")
        return None

    if _mongo_client is not None:
        return _mongo_client

    wc = _map_write_concern(MONGO_WRITE_CONCERN)

    client_kwargs: Dict[str, Any] = {
        "serverSelectionTimeoutMS": MONGO_CONNECT_TIMEOUT_MS,
        "socketTimeoutMS": MONGO_SOCKET_TIMEOUT_MS,
        "maxPoolSize": MONGO_MAX_POOL_SIZE,
        "minPoolSize": MONGO_MIN_POOL_SIZE,
        "retryWrites": MONGO_RETRY_WRITES,
        "readPreference": _map_read_preference(MONGO_READ_PREFERENCE),
        "w": wc.document.get("w"),
    }

    if MONGO_COMPRESSORS:
        client_kwargs["compressors"] = MONGO_COMPRESSORS

    # TLS options (Atlas often uses TLS implicitly in URI; keep these for self-managed clusters)
    if MONGO_TLS:
        client_kwargs["tls"] = True
        if MONGO_TLS_CA_FILE:
            client_kwargs["tlsCAFile"] = MONGO_TLS_CA_FILE

    if MONGO_REPLICA_SET:
        client_kwargs["replicaSet"] = MONGO_REPLICA_SET

    try:
        _mongo_client = MongoClient(MONGO_URI, **client_kwargs)
        _mongo_client.admin.command("ping")
        logging.info(
            "Connected to MongoDB at %s (readPreference=%s, writeConcern=%s)",
            MONGO_URI,
            MONGO_READ_PREFERENCE,
            MONGO_WRITE_CONCERN,
        )
        return _mongo_client
    except Exception as e:
        logging.error("Failed to connect to MongoDB at %s: %s", MONGO_URI, e)
        _mongo_client = None
        return None


def close_mongo_client():
    """
    Close the MongoClient when you are done. Optional, but nice for CLI tools.
    """
    global _mongo_client
    if _mongo_client is not None:
        try:
            _mongo_client.close()
            logging.info("Closed MongoDB connection.")
        except Exception as e:
            logging.warning("Error while closing MongoDB client: %s", e)
    _mongo_client = None


def get_mongo_collections():
    """
    Convenience helper to return (db, providers_col, evidence_col, runs_col)
    or (None, None, None, None) if disabled/unavailable.
    """
    if not MONGO_ENABLED:
        return None, None, None, None
    client = get_mongo_client()
    if not client:
        return None, None, None, None
    db = client[MONGO_DB_NAME]
    providers_col = db[MONGO_PROVIDERS_COLLECTION]
    evidence_col = db[MONGO_EVIDENCE_COLLECTION]
    runs_col = db[MONGO_RUNS_COLLECTION]
    return db, providers_col, evidence_col, runs_col


def _batched(iterable, batch_size: int):
    """
    Yield lists of up to batch_size items from iterable.
    """
    batch = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def _redact_provider_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    """
    Redact PII-like fields in a provider document before writing to Mongo (if REDACT_PII is enabled).
    Mirrors JSON/NDJSON redaction semantics.
    """
    if not globals().get("REDACT_PII", False):
        return doc

    redacted = dict(doc)

    for field_name in [
        "address",
        "phone",
        "primary_email",
        "website",
        "latitude",
        "longitude",
    ]:
        if field_name in redacted:
            redacted[field_name] = None

    if "manual_notes" in redacted:
        redacted["manual_notes"] = None

    if "investigation" in redacted and isinstance(redacted["investigation"], dict):
        inv = dict(redacted["investigation"])
        inv["errors"] = []
        redacted["investigation"] = inv

    return redacted


def _redact_evidence_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    """
    Redact PII-like content in evidence documents if REDACT_PII is enabled.
    """
    if not globals().get("REDACT_PII", False):
        return doc

    redacted = dict(doc)

    if "raw_excerpt" in redacted:
        redacted["raw_excerpt"] = None

    return redacted


def ensure_mongo_indexes(db):
    """
    Create useful indexes on providers, evidence, and runs collections.
    This is idempotent and guarded so it is only run once per process.
    """
    global _mongo_indexes_ensured
    if _mongo_indexes_ensured or not MONGO_INDEX_BOOTSTRAP:
        return

    try:
        providers_col = db[MONGO_PROVIDERS_COLLECTION]
        evidence_col = db[MONGO_EVIDENCE_COLLECTION]
        runs_col = db[MONGO_RUNS_COLLECTION]

        # Providers
        providers_col.create_index("id", unique=True, name="providers_id_unique")
        providers_col.create_index(
            [("risk_tier", 1), ("status", 1)],
            name="providers_risk_status",
        )
        providers_col.create_index(
            [("_run_id", 1), ("risk_tier", 1)],
            name="providers_run_risk",
        )
        providers_col.create_index(
            [("_tag", 1), ("risk_tier", 1), ("status", 1)],
            name="providers_tag_risk_status",
        )
        providers_col.create_index(
            [("normalized_name", 1)],
            name="providers_normalized_name",
        )
        providers_col.create_index(
            [("city", 1), ("county", 1), ("state", 1)],
            name="providers_region",
        )
        providers_col.create_index(
            [("_schema_version", 1)],
            name="providers_schema_version",
        )
        if MONGO_SOFT_DELETE:
            providers_col.create_index(
                [("_deleted", 1)],
                name="providers_deleted_flag",
            )

        # Evidence
        evidence_col.create_index(
            [("provider_id", 1), ("severity", 1)],
            name="evidence_provider_severity",
        )
        evidence_col.create_index(
            [("_run_id", 1), ("severity", 1)],
            name="evidence_run_severity",
        )
        evidence_col.create_index(
            [("_tag", 1), ("severity", 1)],
            name="evidence_tag_severity",
        )
        evidence_col.create_index(
            [("_schema_version", 1)],
            name="evidence_schema_version",
        )
        if MONGO_SOFT_DELETE:
            evidence_col.create_index(
                [("_deleted", 1)],
                name="evidence_deleted_flag",
            )

        # Runs
        runs_col.create_index(
            [("run_id", 1)],
            unique=True,
            name="runs_run_id_unique",
        )
        runs_col.create_index(
            [("tag", 1), ("created_at_utc", -1)],
            name="runs_tag_created_at",
        )
        runs_col.create_index(
            [("schema_version", 1)],
            name="runs_schema_version",
        )

        _mongo_indexes_ensured = True
        logging.info("MongoDB indexes ensured on collections: %s, %s, %s",
                     MONGO_PROVIDERS_COLLECTION, MONGO_EVIDENCE_COLLECTION, MONGO_RUNS_COLLECTION)
    except Exception as e:
        logging.error("Error while ensuring MongoDB indexes: %s", e)


def reindex_mongo_collections():
    """
    Optional maintenance helper: force re-indexing the main collections.
    """
    if not MONGO_ENABLED:
        logging.warning("MongoDB integration disabled; cannot reindex.")
        return

    client = get_mongo_client()
    if not client:
        logging.warning("MongoDB client unavailable; cannot reindex.")
        return

    db = client[MONGO_DB_NAME]
    for coll_name in [MONGO_PROVIDERS_COLLECTION, MONGO_EVIDENCE_COLLECTION, MONGO_RUNS_COLLECTION]:
        try:
            res = db[coll_name].reindex()
            logging.info("Reindex result for '%s': %s", coll_name, res)
        except Exception as e:
            logging.error("Error reindexing collection '%s': %s", coll_name, e)


def _log_mongo_error(context: str, err: Exception):
    """
    Centralized Mongo error logging so we can add more structure later.
    """
    if pymongo_errors and isinstance(err, pymongo_errors.BulkWriteError):
        details = err.details or {}
        write_errors = details.get("writeErrors", [])
        logging.error(
            "Mongo BulkWriteError in %s: %s (first error: %s)",
            context,
            err,
            write_errors[0] if write_errors else "n/a",
        )
    else:
        logging.error("Mongo error in %s: %s", context, err)


def write_run_to_mongo(providers: List[Provider]):
    """
    Persist providers, evidence, and run metadata into MongoDB collections.
    Respects MONGO_WRITE_MODE and MONGO_DRY_RUN.
    """
    if not MONGO_ENABLED:
        logging.debug("MongoDB integration disabled; skipping Mongo writes.")
        return

    client = get_mongo_client()
    if not client:
        logging.warning("MongoDB client unavailable; skipping Mongo writes.")
        return

    db = client[MONGO_DB_NAME]
    ensure_mongo_indexes(db)

    providers_col = db[MONGO_PROVIDERS_COLLECTION]
    evidence_col = db[MONGO_EVIDENCE_COLLECTION]
    runs_col = db[MONGO_RUNS_COLLECTION]

    run_meta = get_run_metadata()
    run_meta_doc = {
        **run_meta,
        "created_at_utc": now_utc_iso(),
        "provider_count": len(providers),
        "tag": MONGO_TAG,
        "schema_version": MONGO_SCHEMA_VERSION,
    }

    # Aggregate counts
    status_counts: Dict[str, int] = {}
    tier_counts: Dict[str, int] = {}
    for p in providers:
        status = p.status.value if isinstance(p.status, enum.Enum) else str(p.status)
        status_counts[status] = status_counts.get(status, 0) + 1
        tier = p.risk_tier or RiskTier.UNKNOWN.value
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
    run_meta_doc["status_counts"] = status_counts
    run_meta_doc["risk_tier_counts"] = tier_counts

    if MONGO_DRY_RUN:
        logging.info("[Mongo dry-run] Would write run metadata: %s", run_meta_doc)
    else:
        try:
            runs_col.insert_one(run_meta_doc)
        except Exception as e:
            _log_mongo_error("runs_col.insert_one(run_meta_doc)", e)

       # Providers
    if MONGO_DRY_RUN:
        logging.info("[Mongo dry-run] Would write %d provider documents.", len(providers))
    else:
        logging.info(
            "Writing %d providers to MongoDB (%s.%s) with mode=%s",
            len(providers),
            MONGO_DB_NAME,
            MONGO_PROVIDERS_COLLECTION,
            MONGO_WRITE_MODE,
        )

        for batch in _batched(providers, MONGO_BATCH_SIZE):
            docs = []
            for p in batch:
                # 1) serialize without redaction so Mongo gets the full normalized document
                doc = serialize_provider(p, redact=False)

                # 2) attach run metadata / tagging / schema version
                doc["_run_id"] = RUN_ID
                doc["_run_meta"] = run_meta
                doc["_tag"] = MONGO_TAG
                doc["_schema_version"] = MONGO_SCHEMA_VERSION

                # 3) soft-delete flag if enabled
                if MONGO_SOFT_DELETE:
                    doc.setdefault("_deleted", False)

                # 4) apply PII redaction last, only if enabled
                if REDACT_PII:
                    doc = _redact_provider_doc(doc)

                docs.append(doc)

            try:
                if MONGO_WRITE_MODE == "insert":
                    providers_col.insert_many(docs, ordered=False)
                elif MONGO_WRITE_MODE == "replace":
                    for doc in docs:
                        providers_col.replace_one({"id": doc.get("id")}, doc, upsert=True)
                else:  # upsert
                    for doc in docs:
                        providers_col.update_one({"id": doc.get("id")}, {"$set": doc}, upsert=True)
            except Exception as e:
                _log_mongo_error("providers batch write", e)
    # Evidence
    evidence_items = list(EVIDENCE_REGISTRY.values())
    if MONGO_DRY_RUN:
        logging.info("[Mongo dry-run] Would write %d evidence documents.", len(evidence_items))
    else:
        logging.info("Writing %d evidence items to MongoDB (%s.%s)",
                     len(evidence_items), MONGO_DB_NAME, MONGO_EVIDENCE_COLLECTION)
        for batch in _batched(evidence_items, MONGO_BATCH_SIZE):
            docs = []
            for ev in batch:
                doc = asdict(ev)
                doc["_run_id"] = RUN_ID
                doc["_run_meta"] = run_meta
                doc["_tag"] = MONGO_TAG
                doc["_schema_version"] = MONGO_SCHEMA_VERSION
                if MONGO_SOFT_DELETE:
                    doc.setdefault("_deleted", False)
                doc = _redact_evidence_doc(doc)
                docs.append(doc)
            try:
                evidence_col.insert_many(docs, ordered=False)
            except Exception as e:
                _log_mongo_error("evidence batch write", e)

    logging.info("MongoDB write complete for run_id=%s", RUN_ID)


# -------------------------
# Mongo query helpers (for downstream tooling / interactive use)
# -------------------------

def mongo_fetch_providers_by_risk(
    risk_tiers: Optional[List[str]] = None,
    tag: Optional[str] = None,
    status: Optional[List[str]] = None,
    min_fraud_score: Optional[float] = None,
    max_count: int = 100,
) -> List[Dict[str, Any]]:
    """
    Fetch provider docs by risk tier, optional tag, optional statuses and fraud_score threshold.
    Useful for ad-hoc CLI tools and notebooks.
    """
    if not MONGO_ENABLED:
        logging.warning("MongoDB integration disabled; cannot fetch providers.")
        return []

    client = get_mongo_client()
    if not client:
        logging.warning("MongoDB client unavailable; cannot fetch providers.")
        return []

    db = client[MONGO_DB_NAME]
    providers_col = db[MONGO_PROVIDERS_COLLECTION]

    query: Dict[str, Any] = {}
    if risk_tiers:
        query["risk_tier"] = {"$in": risk_tiers}
    if tag:
        query["_tag"] = tag
    if status:
        query["status"] = {"$in": status}
    if min_fraud_score is not None:
        query["signals.fraud_score"] = {"$gte": float(min_fraud_score)}
    if MONGO_SOFT_DELETE:
        query["_deleted"] = {"$ne": True}

    cursor = (
        providers_col
        .find(query)
        .sort("signals.fraud_score", -1)
        .limit(max_count)
    )
    return list(cursor)


def mongo_fetch_run_metadata(
    run_id: Optional[str] = None,
    tag: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """
    Fetch run metadata documents by run_id or tag.
    """
    if not MONGO_ENABLED:
        logging.warning("MongoDB integration disabled; cannot fetch runs.")
        return []

    client = get_mongo_client()
    if not client:
        logging.warning("MongoDB client unavailable; cannot fetch runs.")
        return []

    db = client[MONGO_DB_NAME]
    runs_col = db[MONGO_RUNS_COLLECTION]

    query: Dict[str, Any] = {}
    if run_id:
        query["run_id"] = run_id
    if tag:
        query["tag"] = tag

    cursor = runs_col.find(query).sort("created_at_utc", -1).limit(limit)
    return list(cursor)


def mongo_update_manual_label(
    provider_id: str,
    manual_label: Optional[str] = None,
    manual_notes: Optional[str] = None,
) -> bool:
    """
    Update manual_label/manual_notes for a single provider by id.
    """
    if not MONGO_ENABLED:
        logging.warning("MongoDB integration disabled; cannot update provider manual label.")
        return False

    client = get_mongo_client()
    if not client:
        logging.warning("MongoDB client unavailable; cannot update provider manual label.")
        return False

    db = client[MONGO_DB_NAME]
    providers_col = db[MONGO_PROVIDERS_COLLECTION]

    update_doc: Dict[str, Any] = {}
    if manual_label is not None:
        update_doc["manual_label"] = manual_label
    if manual_notes is not None:
        update_doc["manual_notes"] = manual_notes

    if not update_doc:
        return False

    try:
        res = providers_col.update_one({"id": provider_id}, {"$set": update_doc})
        return res.modified_count > 0
    except Exception as e:
        _log_mongo_error("mongo_update_manual_label", e)
        return False


def mongo_delete_run_data(
    run_id: str,
    hard_delete: bool = False,
) -> Dict[str, int]:
    """
    Delete all data associated with a given run_id from providers/evidence/runs.
    If hard_delete=False and MONGO_SOFT_DELETE=True, set _deleted=True instead of removing.
    Returns a dict with counts per collection.
    """
    if not MONGO_ENABLED:
        logging.warning("MongoDB integration disabled; cannot delete run data.")
        return {"providers": 0, "evidence": 0, "runs": 0}

    client = get_mongo_client()
    if not client:
        logging.warning("MongoDB client unavailable; cannot delete run data.")
        return {"providers": 0, "evidence": 0, "runs": 0}

    db = client[MONGO_DB_NAME]
    providers_col = db[MONGO_PROVIDERS_COLLECTION]
    evidence_col = db[MONGO_EVIDENCE_COLLECTION]
    runs_col = db[MONGO_RUNS_COLLECTION]

    result = {"providers": 0, "evidence": 0, "runs": 0}

    try:
        if hard_delete or not MONGO_SOFT_DELETE:
            pr_res = providers_col.delete_many({"_run_id": run_id})
            ev_res = evidence_col.delete_many({"_run_id": run_id})
            ru_res = runs_col.delete_many({"run_id": run_id})
            result["providers"] = pr_res.deleted_count
            result["evidence"] = ev_res.deleted_count
            result["runs"] = ru_res.deleted_count
        else:
            pr_res = providers_col.update_many({"_run_id": run_id}, {"$set": {"_deleted": True}})
            ev_res = evidence_col.update_many({"_run_id": run_id}, {"$set": {"_deleted": True}})
            ru_res = runs_col.update_many({"run_id": run_id}, {"$set": {"_deleted": True}})
            result["providers"] = pr_res.modified_count
            result["evidence"] = ev_res.modified_count
            result["runs"] = ru_res.modified_count

        logging.info("Run data deletion (run_id=%s, hard_delete=%s): %s", run_id, hard_delete, result)
    except Exception as e:
        _log_mongo_error("mongo_delete_run_data", e)

    return result


# -------------------------
# JSON Schema builders for MongoDB / Atlas validation
# -------------------------

def build_provider_json_schema() -> Dict[str, Any]:
    """
    Exportable JSON Schema (draft-07-style) for provider documents as stored in MongoDB.
    This is intentionally slightly permissive (additionalProperties allowed) so schema
    does not break on new fields.
    """
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "DaycareProvider",
        "type": "object",
        "required": ["id", "normalized_name", "status", "signals"],
        "properties": {
            "_id": {"description": "MongoDB ObjectId", "bsonType": "objectId"},
            "_run_id": {"type": "string"},
            "_tag": {"type": ["string", "null"]},
            "_schema_version": {"type": ["string", "null"]},
            "id": {"type": "string"},
            "normalized_name": {"type": "string"},
            "raw_names": {
                "type": "array",
                "items": {"type": "string"},
            },
            "address": {"type": ["string", "null"]},
            "city": {"type": ["string", "null"]},
            "county": {"type": ["string", "null"]},
            "state": {"type": ["string", "null"]},
            "postal_code": {"type": ["string", "null"]},
            "phone": {"type": ["string", "null"]},
            "website": {"type": ["string", "null"]},
            "primary_email": {"type": ["string", "null"]},
            "latitude": {"type": ["number", "null"]},
            "longitude": {"type": ["number", "null"]},
            "status": {"type": "string", "enum": [s.value for s in ProviderStatus]},
            "risk_tier": {
                "type": ["string", "null"],
                "enum": [t.value for t in RiskTier] + [None],
            },
            "debug_reasons": {
                "type": "array",
                "items": {"type": "string"},
            },
            "signals": {
                "type": "object",
                "properties": {
                    "discovered_via": {"type": "array", "items": {"type": "string"}},
                    "has_google_listing": {"type": "boolean"},
                    "has_other_ads": {"type": "boolean"},
                    "has_other_listings": {"type": "boolean"},
                    "google_place_id": {"type": ["string", "null"]},
                    "google_rating": {"type": ["number", "null"]},
                    "google_user_ratings_total": {"type": ["integer", "null"]},
                    "google_reviews_recent": {"type": "boolean"},
                    "google_business_status": {"type": ["string", "null"]},
                    "google_open_now": {"type": ["boolean", "null"]},
                    "google_last_review_time": {"type": ["string", "null"], "format": "date-time"},
                    "google_last_review_recency_days": {"type": ["number", "null"]},
                    "has_facebook_page": {"type": "boolean"},
                    "has_x_profile": {"type": "boolean"},
                    "has_linkedin_company": {"type": "boolean"},
                    "social_recent_activity": {"type": "boolean"},
                    "has_secretary_of_state_registration": {"type": "boolean"},
                    "sos_entity_name": {"type": ["string", "null"]},
                    "sos_active": {"type": "boolean"},
                    "has_dol_business_license": {"type": "boolean"},
                    "dol_license_number": {"type": ["string", "null"]},
                    "dol_active": {"type": "boolean"},
                    "has_dcyf_license": {"type": "boolean"},
                    "dcyf_license_number": {"type": ["string", "null"]},
                    "dcyf_active": {"type": "boolean"},
                    "name_mismatch_with_license": {"type": "boolean"},
                    "website_reachable": {"type": "boolean"},
                    "website_http_status": {"type": ["integer", "null"]},
                    "website_title": {"type": ["string", "null"]},
                    "website_meta_description": {"type": ["string", "null"]},
                    "website_has_license_language": {"type": "boolean"},
                    "website_has_dcyf_language": {"type": "boolean"},
                    "website_has_contact_page": {"type": "boolean"},
                    "website_has_photos_keywords": {"type": "boolean"},
                    "website_has_staff_bios_keywords": {"type": "boolean"},
                    "website_last_crawled_utc": {"type": ["string", "null"], "format": "date-time"},
                    "has_geocoded_location": {"type": "boolean"},
                    "visitor_activity_likely": {"type": "boolean"},
                    "city_review_volume_rank": {"type": ["integer", "null"]},
                    "city_review_volume_percentile": {"type": ["number", "null"]},
                    "is_city_low_activity_outlier": {"type": "boolean"},
                    "is_city_high_activity_outlier": {"type": "boolean"},
                    "name_generic_score": {"type": "number"},
                    "name_contains_location_term": {"type": "boolean"},
                    "name_contains_personal_name": {"type": "boolean"},
                    "email_domain_type": {"type": ["string", "null"]},
                    "shared_address_count": {"type": ["integer", "null"]},
                    "shared_phone_count": {"type": ["integer", "null"]},
                    "fraud_score": {"type": "number"},
                    "legitimacy_score": {"type": "number"},
                },
                "additionalProperties": True,
            },
            "investigation": {
                "type": "object",
                "properties": {
                    "steps": {"type": "array", "items": {"type": "string"}},
                    "errors": {"type": "array", "items": {"type": "string"}},
                    "evidence_ids": {"type": "array", "items": {"type": "string"}},
                },
                "additionalProperties": True,
            },
            "manual_label": {"type": ["string", "null"]},
            "manual_notes": {"type": ["string", "null"]},
            "_deleted": {"type": ["boolean", "null"]},
        },
        "additionalProperties": True,
    }


def build_evidence_json_schema() -> Dict[str, Any]:
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "DaycareEvidenceItem",
        "type": "object",
        "required": ["id", "provider_id", "source_type", "label", "severity", "timestamp_utc"],
        "properties": {
            "_id": {"bsonType": "objectId"},
            "_run_id": {"type": "string"},
            "_tag": {"type": ["string", "null"]},
            "_schema_version": {"type": ["string", "null"]},
            "id": {"type": "string"},
            "provider_id": {"type": "string"},
            "source_type": {"type": "string"},
            "label": {"type": "string"},
            "severity": {"type": "string", "enum": [s.value for s in EvidenceSeverity]},
            "timestamp_utc": {"type": "string", "format": "date-time"},
            "description": {"type": "string"},
            "url": {"type": ["string", "null"]},
            "raw_excerpt": {"type": ["string", "null"]},
            "metadata": {"type": "object"},
            "_deleted": {"type": ["boolean", "null"]},
        },
        "additionalProperties": True,
    }


def build_run_json_schema() -> Dict[str, Any]:
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "DaycareRunMetadata",
        "type": "object",
        "required": ["run_id", "run_timestamp_utc", "search_region", "search_keywords"],
        "properties": {
            "_id": {"bsonType": "objectId"},
            "run_id": {"type": "string"},
            "run_timestamp_utc": {"type": "string", "format": "date-time"},
            "search_region": {"type": "string"},
            "search_keywords": {
                "type": "array",
                "items": {"type": "string"},
            },
            "created_at_utc": {"type": "string", "format": "date-time"},
            "provider_count": {"type": "integer"},
            "tag": {"type": ["string", "null"]},
            "schema_version": {"type": ["string", "null"]},
            "status_counts": {
                "type": "object",
                "additionalProperties": {"type": "integer"},
            },
            "risk_tier_counts": {
                "type": "object",
                "additionalProperties": {"type": "integer"},
            },
        },
        "additionalProperties": True,
    }


def save_json_schemas(schema_dir: str):
    """
    Write provider/evidence/run JSON Schemas to schema_dir.
    These can be imported into MongoDB Atlas as JSON Schema validators.
    """
    os.makedirs(schema_dir, exist_ok=True)
    files = {
        "providers.schema.json": build_provider_json_schema(),
        "evidence.schema.json": build_evidence_json_schema(),
        "runs.schema.json": build_run_json_schema(),
    }
    for filename, schema in files.items():
        path = os.path.join(schema_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(schema, f, indent=2)
        logging.info("Wrote JSON Schema to %s", path)
def run_scan(dry_run: bool = False,
             print_summary_only: bool = False) -> List[Provider]:
    """
    Main scan orchestration.
    Returns the list of all providers discovered / processed.
    """
    all_providers: List[Provider] = []

    logging.info("Run ID: %s | Timestamp (UTC): %s", RUN_ID, RUN_TIMESTAMP_UTC)
    logging.info("Search region: %s", SEARCH_REGION)
    logging.info("Keywords: %s", ", ".join(SEARCH_KEYWORDS))

    # 1. Discover via Google Places
    google_providers: List[Provider] = []
    for kw in SEARCH_KEYWORDS:
        places = search_google_places(kw, SEARCH_REGION)
        if MAX_GOOGLE_RESULTS_PER_KEYWORD is not None:
            places = places[:MAX_GOOGLE_RESULTS_PER_KEYWORD]
        google_providers.extend(extract_providers_from_google(places))

    all_providers.extend(google_providers)

    # 2. Discover via ad platforms (scaffold)
    if ENABLE_ADS_DISCOVERY:
        ad_providers = crawl_ad_platforms_for_providers()
        all_providers.extend(ad_providers)

    # 3. Discover via other listings (scaffold)
    if ENABLE_OTHER_LISTINGS_DISCOVERY:
        other_listing_providers = crawl_other_listing_sites_for_providers()
        all_providers.extend(other_listing_providers)

    # 4. Merge / deduplicate
    all_providers = deduplicate_providers(all_providers)
    logging.info("Total unique providers after deduplication: %d", len(all_providers))

    # 5. Name signals (generic/location/personal)
    for provider in all_providers:
        compute_name_signals(provider)

    if dry_run:
        logging.info("Dry run: skipping enrichment, classification, and evidence generation.")
        save_providers_ndjson("providers_discovered.ndjson", all_providers)
        return all_providers

    # 6. Enrich with Google details (county, status, activity, website)
    for provider in all_providers:
        enrich_provider_with_google_details(provider)

    # 7. Website + Social + Government records
    for provider in all_providers:
        if ENABLE_WEBSITE_FETCH:
            fetch_website(provider)
        if ENABLE_SOCIAL_LOOKUP:
            crawl_social_profiles_for_provider(provider)
        if ENABLE_GOV_LOOKUP:
            enrich_with_government_records(provider)

    # 8. City-level stats and shared-contact patterns
    city_stats = compute_city_stats(all_providers)
    enrich_providers_with_city_stats(all_providers, city_stats)
    compute_shared_contact_stats(all_providers)

    # 9. Classification and scoring
    for provider in all_providers:
        classify_provider(provider)

    # 10. Split by classification
    fraud_licensed_not_listed = [p for p in all_providers if p.status == ProviderStatus.LICENSED_BUT_NOT_LISTED]
    legit_licensed_active = [p for p in all_providers if p.status == ProviderStatus.LICENSED_AND_ACTIVE]
    fraud_unlicensed_listed = [p for p in all_providers if p.status == ProviderStatus.UNLICENSED_BUT_LISTED]
    unknown = [p for p in all_providers if p.status == ProviderStatus.UNKNOWN]

    logging.info("Summary:")
    logging.info("  Licensed but not listed (fraud): %d", len(fraud_licensed_not_listed))
    logging.info("  Licensed and active (legit):     %d", len(legit_licensed_active))
    logging.info("  Unlicensed but listed (fraud):   %d", len(fraud_unlicensed_listed))
    logging.info("  Unknown:                         %d", len(unknown))

    if print_summary_only:
        # Simple human-readable summary including risk tiers
        tier_counts: Dict[str, int] = {}
        for p in all_providers:
            tier = p.risk_tier or RiskTier.UNKNOWN.value
            tier_counts[tier] = tier_counts.get(tier, 0) + 1

        print("\n=== Classification Summary ===")
        print(f"Total providers: {len(all_providers)}")
        print(f"  Licensed but not listed (fraud): {len(fraud_licensed_not_listed)}")
        print(f"  Licensed and active (legit):     {len(legit_licensed_active)}")
        print(f"  Unlicensed but listed (fraud):   {len(fraud_unlicensed_listed)}")
        print(f"  Unknown:                         {len(unknown)}")
        print("\nRisk tiers:")
        for tier in [t.value for t in RiskTier]:
            if tier in tier_counts:
                print(f"  {tier:9s}: {tier_counts[tier]}")
        print("=============================\n")

    # 10b. Optional Top-N printout for quick human triage
    if PRINT_TOP_N and PRINT_TOP_N > 0:
        _print_top_n_providers(all_providers, PRINT_TOP_N)

    # 11. Grouped JSONs per result type
    save_grouped_json("licensed_but_not_listed.json", fraud_licensed_not_listed)
    save_grouped_json("licensed_and_active.json", legit_licensed_active)
    save_grouped_json("unlicensed_but_listed.json", fraud_unlicensed_listed)
    save_grouped_json("unknown.json", unknown)

    # 12. Full NDJSON dump of all providers
    save_providers_ndjson("providers_all.ndjson", all_providers)

    # 12b. Optional high-risk NDJSON filtered by fraud score / tier
    if MIN_FRAUD_SCORE_FOR_HIGHRISK_OUTPUT is not None or RISK_TIERS_FOR_HIGHRISK_OUTPUT:
        filtered: List[Provider] = []
        for p in all_providers:
            s = p.signals
            if MIN_FRAUD_SCORE_FOR_HIGHRISK_OUTPUT is not None and s.fraud_score < MIN_FRAUD_SCORE_FOR_HIGHRISK_OUTPUT:
                continue
            if RISK_TIERS_FOR_HIGHRISK_OUTPUT:
                tier = p.risk_tier or RiskTier.UNKNOWN.value
                if tier not in RISK_TIERS_FOR_HIGHRISK_OUTPUT:
                    continue
            filtered.append(p)
        if filtered:
            save_providers_ndjson("providers_high_risk.ndjson", filtered)
            logging.info(
                "Wrote %d providers to providers_high_risk.ndjson using filters (min_fraud_score=%s, tiers=%s)",
                len(filtered),
                MIN_FRAUD_SCORE_FOR_HIGHRISK_OUTPUT,
                ",".join(RISK_TIERS_FOR_HIGHRISK_OUTPUT) if RISK_TIERS_FOR_HIGHRISK_OUTPUT else "ANY",
            )
        else:
            logging.info("No providers matched the high-risk filters; no providers_high_risk.ndjson written.")

    # 13. Evidence NDJSON
    save_evidence_registry()

    # 14. Optional CSV summary
    if WRITE_CSV_SUMMARY:
        save_providers_csv("providers_summary.csv", all_providers)

    return all_providers

# =========================
# CLI
# =========================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan for potentially fraudulent childcare/daycare providers using "
            "Google Places and supporting signals; export JSON/NDJSON/CSV; "
            "optionally persist runs to MongoDB / MongoDB Atlas and emit JSON Schemas."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # ------------------------------------------------------------------
    # Region / keywords
    # ------------------------------------------------------------------
    parser.add_argument(
        "-r", "--region",
        help="Search region appended to each keyword query (e.g., 'Washington State', 'Seattle WA').",
    )
    parser.add_argument(
        "-k", "--keyword",
        action="append",
        help=(
            "Search keyword; may be given multiple times. "
            "If omitted and no --keywords-file is provided, built-in defaults are used."
        ),
    )
    parser.add_argument(
        "--keywords-file",
        help="File with one keyword per line. Combined with any --keyword arguments.",
    )

    # ------------------------------------------------------------------
    # Directories
    # ------------------------------------------------------------------
    parser.add_argument(
        "--output-dir",
        default=OUTPUT_DIR,
        help="Directory for JSON/NDJSON/CSV output files.",
    )
    parser.add_argument(
        "--evidence-dir",
        default=EVIDENCE_DIR,
        help="Directory for evidence NDJSON output.",
    )

    # ------------------------------------------------------------------
    # Timing / thresholds
    # ------------------------------------------------------------------
    parser.add_argument(
        "--api-sleep",
        type=float,
        default=API_SLEEP_SECONDS,
        help="Delay in seconds between Google API calls.",
    )
    parser.add_argument(
        "--review-recent-days",
        type=int,
        default=GOOGLE_REVIEW_RECENT_DAYS,
        help="Number of days considered 'recent' for Google reviews.",
    )
    parser.add_argument(
        "--http-timeout",
        type=int,
        default=HTTP_TIMEOUT,
        help="Timeout in seconds for HTTP requests to provider websites.",
    )
    parser.add_argument(
        "--max-google-results-per-keyword",
        type=int,
        default=None,
        help="Optional cap on number of Google Places results processed per keyword.",
    )

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity.",
    )

    # ------------------------------------------------------------------
    # Feature toggles
    # ------------------------------------------------------------------
    parser.add_argument(
        "--no-ads",
        action="store_true",
        help="Disable ad-platform discovery (currently a scaffold).",
    )
    parser.add_argument(
        "--no-other-listings",
        action="store_true",
        help="Disable discovery from other listing sites (Yelp, Yellow Pages, etc., currently a scaffold).",
    )
    parser.add_argument(
        "--no-website",
        action="store_true",
        help="Disable website fetch and analysis for providers.",
    )
    parser.add_argument(
        "--no-social",
        action="store_true",
        help="Disable social profile lookup (placeholder).",
    )
    parser.add_argument(
        "--no-gov",
        action="store_true",
        help="Disable WA government/licensing lookups.",
    )

    # ------------------------------------------------------------------
    # Modes
    # ------------------------------------------------------------------
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Discover providers and deduplicate only; skip enrichment, classification, "
            "and evidence scoring. Writes providers_discovered.ndjson."
        ),
    )
    parser.add_argument(
        "--print-summary-only",
        action="store_true",
        help="Print a human-readable classification summary to stdout (files are still written).",
    )

    # ------------------------------------------------------------------
    # Additional output controls
    # ------------------------------------------------------------------
    parser.add_argument(
        "--print-top-n",
        type=int,
        default=0,
        help="If > 0, print a brief table of the top-N most suspicious providers (by fraud_score) to stdout.",
    )
    parser.add_argument(
        "--min-fraud-score",
        type=float,
        default=None,
        help=(
            "If set, write an additional NDJSON file 'providers_high_risk.ndjson' with "
            "providers whose fraud_score >= this value."
        ),
    )
    parser.add_argument(
        "--risk-tier-include",
        action="append",
        choices=[t.value for t in RiskTier],
        help=(
            "Optional filter for 'providers_high_risk.ndjson'; may be given multiple times "
            "(e.g., --risk-tier-include critical --risk-tier-include high)."
        ),
    )
    parser.add_argument(
        "--redact-pii",
        action="store_true",
        help=(
            "Redact PII-like fields (address, phone, email, website, coords, evidence excerpts) "
            "in JSON/NDJSON output, for safe sharing."
        ),
    )
    parser.add_argument(
        "--no-csv-summary",
        action="store_true",
        help="Disable writing providers_summary.csv.",
    )
    parser.add_argument(
        "--status-include",
        action="append",
        choices=[s.value for s in ProviderStatus],
        help=(
            "Optional list of provider statuses to include in NDJSON/CSV summaries "
            "(e.g., 'unlicensed_but_listed'). If omitted, all statuses are included."
        ),
    )

    # ------------------------------------------------------------------
    # Run labeling / scenario control
    # ------------------------------------------------------------------
    parser.add_argument(
        "--scenario-name",
        help="Optional free-form label for this run (e.g., 'baseline_2026Q1', 'appeal_packet_build').",
    )
    parser.add_argument(
        "--notes",
        help="Optional short note string to attach to run metadata (not used by scoring).",
    )

    # ------------------------------------------------------------------
    # MongoDB / MongoDB Atlas integration
    # ------------------------------------------------------------------
    parser.add_argument(
        "--mongo-enable",
        action="store_true",
        help="Enable writing scan results to MongoDB / MongoDB Atlas via PyMongo.",
    )
    parser.add_argument(
        "--mongo-uri",
        help=(
            "MongoDB connection URI. For Atlas, use the mongodb+srv connection string. "
            "If omitted, uses env DCS_MONGO_URI or defaults to 'mongodb://localhost:27017'."
        ),
    )
    parser.add_argument(
        "--mongo-db",
        help="MongoDB database name. If omitted, uses env DCS_MONGO_DB or the default 'daycare_fraud_scanner'.",
    )
    parser.add_argument(
        "--mongo-providers-collection",
        default=None,
        help="MongoDB collection name for providers. Defaults to env DCS_MONGO_PROVIDERS_COLL or 'providers'.",
    )
    parser.add_argument(
        "--mongo-evidence-collection",
        default=None,
        help="MongoDB collection name for evidence items. Defaults to env DCS_MONGO_EVIDENCE_COLL or 'evidence'.",
    )
    parser.add_argument(
        "--mongo-runs-collection",
        default=None,
        help="MongoDB collection name for run metadata. Defaults to env DCS_MONGO_RUNS_COLL or 'runs'.",
    )
    parser.add_argument(
        "--mongo-write-mode",
        choices=["insert", "upsert", "replace"],
        default=None,
        help="How to write provider documents into MongoDB (insert, upsert, or replace). Default is 'upsert'.",
    )
    parser.add_argument(
        "--mongo-tag",
        help="Optional string tag to attach to all MongoDB documents for this run (e.g., 'baseline', 'appeal-evidence').",
    )
    parser.add_argument(
        "--mongo-batch-size",
        type=int,
        default=MONGO_BATCH_SIZE,
        help="Batch size to use for bulk MongoDB writes.",
    )
    parser.add_argument(
        "--mongo-dry-run",
        action="store_true",
        help="Connect to MongoDB and validate, but do not write any documents.",
    )

    # ------------------------------------------------------------------
    # JSON Schema emission for MongoDB collections
    # ------------------------------------------------------------------
    parser.add_argument(
        "--emit-json-schemas",
        action="store_true",
        help="After scan, emit MongoDB JSON Schema files for providers/evidence/runs.",
    )
    parser.add_argument(
        "--json-schema-dir",
        default=None,
        help="Directory to write JSON Schema files into. Defaults to '<output-dir>/schemas'.",
    )

    return parser.parse_args()


def main():
    global SEARCH_REGION, SEARCH_KEYWORDS, OUTPUT_DIR, EVIDENCE_DIR
    global API_SLEEP_SECONDS, GOOGLE_REVIEW_RECENT_DAYS, HTTP_TIMEOUT
    global ENABLE_ADS_DISCOVERY, ENABLE_OTHER_LISTINGS_DISCOVERY
    global ENABLE_WEBSITE_FETCH, ENABLE_SOCIAL_LOOKUP, ENABLE_GOV_LOOKUP
    global MAX_GOOGLE_RESULTS_PER_KEYWORD
    global REDACT_PII, WRITE_CSV_SUMMARY
    global MIN_FRAUD_SCORE_FOR_HIGHRISK_OUTPUT, RISK_TIERS_FOR_HIGHRISK_OUTPUT
    global PRINT_TOP_N, STATUSES_FOR_OUTPUT
    global MONGO_ENABLED, MONGO_URI, MONGO_DB_NAME
    global MONGO_PROVIDERS_COLLECTION, MONGO_EVIDENCE_COLLECTION, MONGO_RUNS_COLLECTION
    global MONGO_WRITE_MODE, MONGO_TAG, MONGO_BATCH_SIZE, MONGO_DRY_RUN

    args = parse_args()

    # Logging level
    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    logging.getLogger().setLevel(log_level)

    # ------------------------------------------------------------------
    # Keywords: CLI overrides defaults if provided
    # ------------------------------------------------------------------
    if args.keyword or args.keywords_file:
        kw_list: List[str] = []
        if args.keyword:
            kw_list.extend(args.keyword)
        if args.keywords_file:
            try:
                with open(args.keywords_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            kw_list.append(line)
            except Exception as e:
                logging.error("Failed to read keywords file '%s': %s", args.keywords_file, e)

        # Deduplicate while preserving order
        seen = set()
        deduped: List[str] = []
        for kw in kw_list:
            if kw not in seen:
                seen.add(kw)
                deduped.append(kw)
        if deduped:
            SEARCH_KEYWORDS = deduped
    # else: use module-level SEARCH_KEYWORDS defaults

    if args.region:
        SEARCH_REGION = args.region

    # ------------------------------------------------------------------
    # Core config
    # ------------------------------------------------------------------
    OUTPUT_DIR = args.output_dir
    EVIDENCE_DIR = args.evidence_dir
    API_SLEEP_SECONDS = args.api_sleep
    GOOGLE_REVIEW_RECENT_DAYS = args.review_recent_days
    HTTP_TIMEOUT = args.http_timeout
    MAX_GOOGLE_RESULTS_PER_KEYWORD = args.max_google_results_per_keyword

    ENABLE_ADS_DISCOVERY = not args.no_ads
    ENABLE_OTHER_LISTINGS_DISCOVERY = not args.no_other_listings
    ENABLE_WEBSITE_FETCH = not args.no_website
    ENABLE_SOCIAL_LOOKUP = not args.no_social
    ENABLE_GOV_LOOKUP = not args.no_gov

    REDACT_PII = args.redact_pii
    WRITE_CSV_SUMMARY = not args.no_csv_summary
    MIN_FRAUD_SCORE_FOR_HIGHRISK_OUTPUT = args.min_fraud_score
    RISK_TIERS_FOR_HIGHRISK_OUTPUT = args.risk_tier_include or []
    PRINT_TOP_N = args.print_top_n
    STATUSES_FOR_OUTPUT = args.status_include or []

    if args.scenario_name:
        logging.info("Scenario name: %s", args.scenario_name)
    if args.notes:
        logging.info("Run notes: %s", args.notes)

    # ------------------------------------------------------------------
    # Mongo config
    # ------------------------------------------------------------------
    MONGO_ENABLED = bool(args.mongo_enable)
    if args.mongo_uri:
        MONGO_URI = args.mongo_uri
    if args.mongo_db:
        MONGO_DB_NAME = args.mongo_db
    if args.mongo_providers_collection:
        MONGO_PROVIDERS_COLLECTION = args.mongo_providers_collection
    if args.mongo_evidence_collection:
        MONGO_EVIDENCE_COLLECTION = args.mongo_evidence_collection
    if args.mongo_runs_collection:
        MONGO_RUNS_COLLECTION = args.mongo_runs_collection
    if args.mongo_write_mode:
        MONGO_WRITE_MODE = args.mongo_write_mode
    if args.mongo_tag:
        MONGO_TAG = args.mongo_tag

    MONGO_BATCH_SIZE = args.mongo_batch_size
    MONGO_DRY_RUN = args.mongo_dry_run

    # ------------------------------------------------------------------
    # Run the scan
    # ------------------------------------------------------------------
    providers = run_scan(dry_run=args.dry_run, print_summary_only=args.print_summary_only)

    # ------------------------------------------------------------------
    # Mongo persistence
    # ------------------------------------------------------------------
    if MONGO_ENABLED:
        write_run_to_mongo(providers)

    # ------------------------------------------------------------------
    # JSON Schema emission
    # ------------------------------------------------------------------
    if args.emit_json_schemas:
        schema_dir = args.json_schema_dir or os.path.join(OUTPUT_DIR, "schemas")
        save_json_schemas(schema_dir)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    if MONGO_ENABLED:
        close_mongo_client()


if __name__ == "__main__":
    main()
