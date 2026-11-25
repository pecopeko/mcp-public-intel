"""Six zero-API-key live public intelligence tools for MCP agents."""

from __future__ import annotations

import email.utils
import html
import json
import math
import re
import time
import xml.etree.ElementTree as ET
from datetime import date, datetime, timezone
from typing import TYPE_CHECKING, Any, Callable
from urllib.parse import urljoin, urlparse

import httpx

from mcp_public_intel.http_client import (
    DEFAULT_USER_AGENT,
    RateLimiter,
    SSRFError,
    assert_safe_public_url,
    build_sec_user_agent,
    html_to_markdown,
    html_to_plain_text,
    parse_xml_safely,
    safe_http_get,
)

# ---------------------------------------------------------------------------
# Constants & Regexes
# ---------------------------------------------------------------------------

_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")
_SUBSTACK_HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")
_APPLE_ID_RE = re.compile(r"(?:^id|/id)(\d{5,15})(?:\D|$)", re.IGNORECASE)
_EMAIL_SEARCH_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

_ANNUAL_FORMS = frozenset({"10-K", "10-K/A", "20-F", "20-F/A", "40-F", "40-F/A"})
_QUARTERLY_FORMS = frozenset({"10-Q", "10-Q/A"})
_KEY_SUBMISSION_FORMS = ("10-K", "10-Q", "8-K", "20-F", "40-F", "S-1")

_XBRL_DURATION_USD: dict[str, tuple[str, ...]] = {
    "revenue": (
        "RevenueFromContractWithCustomerExcludingAssessedTax",
        "RevenueFromContractWithCustomerIncludingAssessedTax",
        "Revenues",
        "SalesRevenueNet",
        "InterestAndDividendIncomeOperating",
        "RealEstateRevenueNet",
    ),
    "net_income": ("NetIncomeLoss", "ProfitLoss"),
    "operating_income": ("OperatingIncomeLoss",),
    "operating_cash_flow": ("NetCashProvidedByUsedInOperatingActivities",),
}

_XBRL_INSTANT_USD: dict[str, tuple[str, ...]] = {
    "assets": ("Assets",),
    "liabilities": ("Liabilities",),
    "stockholders_equity": ("StockholdersEquity",),
    "cash_and_equivalents": (
        "CashAndCashEquivalentsAtCarryingValue",
        "CashCashEquivalentsRestrictedCashAndRestrictedCashEquivalents",
    ),
}

_XBRL_INSTANT_SHARES: tuple[tuple[str, str], ...] = (
    ("dei", "EntityCommonStockSharesOutstanding"),
    ("us-gaap", "CommonStockSharesOutstanding"),
)

_XBRL_DURATION_SHARES: tuple[tuple[str, str], ...] = (
    ("us-gaap", "WeightedAverageNumberOfDilutedSharesOutstanding"),
    ("us-gaap", "WeightedAverageNumberOfSharesOutstandingBasic"),
)

_SEC_TICKER_CACHE: dict[str, str] | None = None
_SEC_RATE_LIMITER = RateLimiter(max_per_second=8.0)

_ATS_PROVIDERS = frozenset({"greenhouse", "lever", "ashby"})

_SENIORITY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("executive", re.compile(r"\b(?:chief\s+\w+\s+officer|cto|ceo|cfo|coo|ciso|vp|vice\s+president)\b", re.I)),
    ("director", re.compile(r"\b(?:senior\s+director|head\s+of|director)\b", re.I)),
    ("manager", re.compile(r"\b(?:engineering\s+manager|manager|em)\b", re.I)),
    ("principal", re.compile(r"\b(?:distinguished|fellow|principal)\b", re.I)),
    ("staff", re.compile(r"\b(?:senior\s+staff|staff)\b", re.I)),
    ("lead", re.compile(r"\b(?:tech\s+lead|team\s+lead|lead)\b", re.I)),
    ("senior", re.compile(r"\b(?:senior|sr\.?)\b", re.I)),
    ("intern", re.compile(r"\b(?:intern|internship|co-op)\b", re.I)),
    ("entry", re.compile(r"\b(?:junior|jr\.?|entry[- ]level|new\s+grad|associate)\b", re.I)),
)

_SALARY_RANGE_RE = re.compile(
    r"(?P<cur>[$£€]|USD\s*|EUR\s*|GBP\s*)"
    r"(?P<low>\d{2,3}(?:,\d{3})+|\d{2,3}(?:\.\d+)?[kK])"
    r"\s*(?:-|–|—|to)\s*"
    r"(?:[$£€]|USD\s*|EUR\s*|GBP\s*)?"
    r"(?P<high>\d{2,3}(?:,\d{3})+|\d{2,3}(?:\.\d+)?[kK])"
)

_TECH_TAG_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Python", re.compile(r"\bpython\b", re.I)),
    ("TypeScript", re.compile(r"\btypescript\b", re.I)),
    ("JavaScript", re.compile(r"\bjavascript\b", re.I)),
    ("Go", re.compile(r"\bgolang\b|\bGo\b(?=\s*[,/)|&]|\s+(?:or|and|engineer|developer|backend|services?))")),
    ("Rust", re.compile(r"\brust\b", re.I)),
    ("C++", re.compile(r"(?<![A-Za-z0-9])c\+\+(?![A-Za-z0-9])", re.I)),
    ("C#", re.compile(r"(?<![A-Za-z0-9])c#(?![A-Za-z0-9])", re.I)),
    ("Java", re.compile(r"\bjava\b", re.I)),
    ("Kotlin", re.compile(r"\bkotlin\b", re.I)),
    ("Swift", re.compile(r"\bswift\b", re.I)),
    ("Ruby", re.compile(r"\bruby\b", re.I)),
    ("Scala", re.compile(r"\bscala\b", re.I)),
    ("SQL", re.compile(r"\bsql\b", re.I)),
    ("PostgreSQL", re.compile(r"\bpostgres(?:ql)?\b", re.I)),
    ("MySQL", re.compile(r"\bmysql\b", re.I)),
    ("Redis", re.compile(r"\bredis\b", re.I)),
    ("Kafka", re.compile(r"\bkafka\b", re.I)),
    ("Spark", re.compile(r"\b(?:apache\s+)?spark\b", re.I)),
    ("Snowflake", re.compile(r"\bsnowflake\b", re.I)),
    ("PyTorch", re.compile(r"\bpytorch\b", re.I)),
    ("TensorFlow", re.compile(r"\btensorflow\b", re.I)),
    ("JAX", re.compile(r"\bjax\b", re.I)),
    ("CUDA", re.compile(r"\bcuda\b", re.I)),
    ("LLM", re.compile(r"\b(?:llms?|large\s+language\s+models?)\b", re.I)),
    ("RAG", re.compile(r"\bRAG\b")),
    ("MCP", re.compile(r"\b(?:MCP|model\s+context\s+protocol)\b")),
    ("React", re.compile(r"\breact(?:\.js|js)?\b", re.I)),
    ("Next.js", re.compile(r"\bnext\.?js\b", re.I)),
    ("Vue", re.compile(r"\bvue(?:\.js|js)?\b", re.I)),
    ("Node.js", re.compile(r"\bnode\.?js\b", re.I)),
    ("FastAPI", re.compile(r"\bfastapi\b", re.I)),
    ("Django", re.compile(r"\bdjango\b", re.I)),
    ("GraphQL", re.compile(r"\bgraphql\b", re.I)),
    ("gRPC", re.compile(r"\bgrpc\b", re.I)),
    ("Docker", re.compile(r"\bdocker\b", re.I)),
    ("Kubernetes", re.compile(r"\b(?:kubernetes|k8s)\b", re.I)),
    ("Terraform", re.compile(r"\bterraform\b", re.I)),
    ("AWS", re.compile(r"\baws\b", re.I)),
    ("GCP", re.compile(r"\b(?:gcp|google\s+cloud)\b", re.I)),
    ("Azure", re.compile(r"\bazure\b", re.I)),
    ("Linux", re.compile(r"\blinux\b", re.I)),
    ("Solidity", re.compile(r"\bsolidity\b", re.I)),
)

_TIMING_LINE_RE = re.compile(
    r"^\s*(\d{1,3}:\d{2}(?::\d{2})?(?:[.,]\d{1,3})?)\s*-->\s*(\d{1,3}:\d{2}(?::\d{2})?(?:[.,]\d{1,3})?)(?:\s+.*)?$"
)
_VTT_SPEAKER_RE = re.compile(r"<v(?:\.[^>\s]+)?\s+([^>]+)>(.*?)(?:</v>|$)", re.DOTALL)
_INLINE_TAG_RE = re.compile(r"<[^>]+>")
_TXT_TIMESTAMP_LINE_RE = re.compile(
    r"^\s*[\[(](\d{1,3}:\d{2}(?::\d{2})?(?:[.,]\d{1,3})?)[\])]\s*(.+)$"
)
_TRANSCRIPT_FORMAT_PRIORITY: dict[str, int] = {
    "json": 0,
    "vtt": 1,
    "srt": 2,
    "txt": 3,
}

# ---------------------------------------------------------------------------
# Shared Helpers
# ---------------------------------------------------------------------------


def _clamp_int(value: Any, default: int, minimum: int, maximum: int, field_name: str) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        try:
            if isinstance(value, bool):
                raise ValueError
            value = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Parameter '{field_name}' must be an integer.") from exc
    return max(minimum, min(value, maximum))


def _trim_text(text: str, max_chars: int) -> tuple[str, bool]:
    if len(text) <= max_chars:
        return text, False
    return text[:max_chars].rstrip() + "...", True


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1].lower()
    return tag.lower()


def _child_text(parent: ET.Element, *names: str) -> str:
    wanted = {n.lower() for n in names}
    for child in parent:
        if _local_name(child.tag) in wanted:
            txt = "".join(child.itertext()).strip()
            if txt:
                return txt
    return ""


def _parse_datetime_utc(raw_value: str | None) -> datetime | None:
    if not raw_value:
        return None
    text = str(raw_value).strip()
    if not text:
        return None
    try:
        normalized = text.replace("Z", "+00:00")
        if len(normalized) == 10 and _ISO_DATE_RE.match(normalized):
            normalized = f"{normalized}T00:00:00+00:00"
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass
    try:
        dt = email.utils.parsedate_to_datetime(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _make_client(user_agent: str = DEFAULT_USER_AGENT, timeout: float = 20.0) -> httpx.Client:
    import httpx

    return httpx.Client(
        timeout=timeout,
        headers={"User-Agent": user_agent, "Accept": "application/json"},
        follow_redirects=False,
    )


# ---------------------------------------------------------------------------
# Tool 1: sec_company_financials
# ---------------------------------------------------------------------------


def _normalize_cik(raw: str) -> str:
    cleaned = str(raw or "").strip().upper()
    if cleaned.startswith("CIK"):
        cleaned = cleaned[3:].strip()
    digits = re.sub(r"\D", "", cleaned)
    if not digits or len(digits) > 10:
        raise ValueError(f"Invalid SEC CIK: {raw!r}")
    return digits.zfill(10)


def _period_days(row: dict[str, Any]) -> int | None:
    start_s = str(row.get("start") or "").strip()
    end_s = str(row.get("end") or "").strip()
    if not start_s or not end_s:
        return None
    try:
        return (date.fromisoformat(end_s[:10]) - date.fromisoformat(start_s[:10])).days
    except ValueError:
        return None


def _is_annual_xbrl_row(row: dict[str, Any]) -> bool:
    form = str(row.get("form") or "").upper()
    fp = str(row.get("fp") or "").upper()
    return form in _ANNUAL_FORMS or fp == "FY"


def _is_quarterly_xbrl_row(row: dict[str, Any]) -> bool:
    form = str(row.get("form") or "").upper()
    fp = str(row.get("fp") or "").upper()
    return form in _QUARTERLY_FORMS or fp in {"Q1", "Q2", "Q3"}


def _format_xbrl_fact(tag: str, row: dict[str, Any], unit: str) -> dict[str, Any]:
    return {
        "tag": tag,
        "val": row.get("val"),
        "unit": unit,
        "start": row.get("start"),
        "end": row.get("end"),
        "filed": row.get("filed"),
        "form": row.get("form"),
        "fy": row.get("fy"),
        "fp": row.get("fp"),
        "period_days": _period_days(row),
    }


def _select_best_xbrl_fact(
    facts_root: dict[str, Any],
    ns_tag_pairs: tuple[tuple[str, str], ...],
    *,
    unit: str,
    period_kind: str,
    is_duration: bool,
) -> dict[str, Any] | None:
    candidates: list[tuple[tuple[str, int, str], str, dict[str, Any]]] = []
    for priority_idx, (ns_name, tag) in enumerate(ns_tag_pairs):
        ns_obj = facts_root.get(ns_name)
        if not isinstance(ns_obj, dict):
            continue
        tag_obj = ns_obj.get(tag)
        if not isinstance(tag_obj, dict):
            continue
        rows = ((tag_obj.get("units") or {}).get(unit)) or []
        if not isinstance(rows, list) or not rows:
            continue

        if period_kind == "annual":
            filtered = [r for r in rows if isinstance(r, dict) and _is_annual_xbrl_row(r)]
            if is_duration:
                full_year = [
                    r
                    for r in filtered
                    if (_period_days(r) is None or (_period_days(r) or 0) >= 300)
                ]
                if full_year:
                    filtered = full_year
        else:
            filtered = [r for r in rows if isinstance(r, dict) and _is_quarterly_xbrl_row(r)]
            if is_duration:
                single_q = [
                    r
                    for r in filtered
                    if (_period_days(r) is not None and 60 <= (_period_days(r) or 0) <= 120)
                ]
                if single_q:
                    filtered = single_q

        for row in filtered:
            end_str = str(row.get("end") or "")
            filed_str = str(row.get("filed") or "")
            if not end_str and not filed_str:
                continue
            rank_key = (end_str, -priority_idx, filed_str)
            candidates.append((rank_key, tag, row))

    if not candidates:
        return None
    _, best_tag, best_row = max(candidates, key=lambda item: item[0])
    return _format_xbrl_fact(best_tag, best_row, unit=unit)


def extract_sec_financials_from_xbrl(companyfacts_json: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Extract structured annual (10-K) vs quarterly (10-Q) XBRL metrics including ASC 606 and shares."""
    facts_root = companyfacts_json.get("facts")
    if not isinstance(facts_root, dict):
        return {"annual": {}, "quarterly": {}}

    annual: dict[str, Any] = {}
    quarterly: dict[str, Any] = {}

    for concept, tags in _XBRL_DURATION_USD.items():
        pairs = tuple(("us-gaap", tag) for tag in tags)
        ann = _select_best_xbrl_fact(
            facts_root, pairs, unit="USD", period_kind="annual", is_duration=True
        )
        if ann is not None:
            annual[concept] = ann
        qtr = _select_best_xbrl_fact(
            facts_root, pairs, unit="USD", period_kind="quarterly", is_duration=True
        )
        if qtr is not None:
            quarterly[concept] = qtr

    for concept, tags in _XBRL_INSTANT_USD.items():
        pairs = tuple(("us-gaap", tag) for tag in tags)
        ann = _select_best_xbrl_fact(
            facts_root, pairs, unit="USD", period_kind="annual", is_duration=False
        )
        if ann is not None:
            annual[concept] = ann
        qtr = _select_best_xbrl_fact(
            facts_root, pairs, unit="USD", period_kind="quarterly", is_duration=False
        )
        if qtr is not None:
            quarterly[concept] = qtr

    for period_kind, target in (("annual", annual), ("quarterly", quarterly)):
        shares_out = _select_best_xbrl_fact(
            facts_root,
            _XBRL_INSTANT_SHARES,
            unit="shares",
            period_kind=period_kind,
            is_duration=False,
        )
        if shares_out is not None:
            target["shares_outstanding"] = shares_out

        weighted_shares = _select_best_xbrl_fact(
            facts_root,
            _XBRL_DURATION_SHARES,
            unit="shares",
            period_kind=period_kind,
            is_duration=True,
        )
        if weighted_shares is not None:
            target["weighted_average_shares_diluted"] = weighted_shares

    return {"annual": annual, "quarterly": quarterly}


def _parse_sec_submissions(submissions_json: dict[str, Any], limit: int = 10) -> dict[str, Any]:
    recent = ((submissions_json.get("filings") or {}).get("recent")) or {}
    form_list = recent.get("form") or []
    acc_list = recent.get("accessionNumber") or []
    date_list = recent.get("filingDate") or []
    report_date_list = recent.get("reportDate") or []
    doc_list = recent.get("primaryDocument") or []
    desc_list = recent.get("primaryDocDescription") or []
    items_list = recent.get("items") or []

    cik = str(submissions_json.get("cik") or "").zfill(10)
    cik_num = str(int(cik)) if cik.isdigit() else cik
    wanted = {f.upper() for f in _KEY_SUBMISSION_FORMS}
    filings: list[dict[str, Any]] = []

    for idx, form_name in enumerate(form_list):
        if str(form_name).upper() not in wanted:
            continue
        acc = str(acc_list[idx]) if idx < len(acc_list) else ""
        doc = str(doc_list[idx]) if idx < len(doc_list) else ""
        acc_nodash = acc.replace("-", "")
        edgar_url = (
            f"https://www.sec.gov/Archives/edgar/data/{cik_num}/{acc_nodash}/{doc}"
            if acc_nodash and doc
            else ""
        )
        index_url = (
            f"https://www.sec.gov/Archives/edgar/data/{cik_num}/{acc_nodash}/{acc}-index.htm"
            if acc_nodash and acc
            else ""
        )
        filings.append(
            {
                "form": form_name,
                "filing_date": date_list[idx] if idx < len(date_list) else None,
                "report_date": report_date_list[idx] if idx < len(report_date_list) else None,
                "accession_number": acc,
                "primary_document": doc,
                "description": desc_list[idx] if idx < len(desc_list) else "",
                "items": items_list[idx] if idx < len(items_list) else [],
                "edgar_url": edgar_url,
                "filing_index_url": index_url,
            }
        )
        if len(filings) >= limit:
            break

    return {
        "cik": cik,
        "entity_name": submissions_json.get("name"),
        "tickers": submissions_json.get("tickers") or [],
        "exchanges": submissions_json.get("exchanges") or [],
        "sic": submissions_json.get("sic"),
        "sic_description": submissions_json.get("sicDescription"),
        "fiscal_year_end": submissions_json.get("fiscalYearEnd"),
        "recent_filings": filings,
    }


def sec_company_financials(
    ticker_or_cik: str,
    contact_email: str | None = None,
    *,
    client: httpx.Client | None = None,
    rate_limiter: RateLimiter | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Fetch official SEC EDGAR submissions & ASC 606 XBRL annual/quarterly financials."""
    global _SEC_TICKER_CACHE

    token = str(ticker_or_cik or "").strip().upper()
    if not token:
        raise ValueError("Parameter 'ticker_or_cik' must not be empty.")

    user_agent = build_sec_user_agent(contact_email)
    headers = {"User-Agent": user_agent, "Accept": "application/json"}
    own_client = client is None
    active = client if client is not None else _make_client(user_agent=user_agent)
    if rate_limiter is not None:
        limiter = rate_limiter
    elif own_client:
        limiter = _SEC_RATE_LIMITER
    else:
        limiter = RateLimiter(max_per_second=8.0, sleep_fn=sleep_fn)

    try:
        raw_digits = token[3:].strip() if token.startswith("CIK") else token
        if raw_digits.isdigit():
            cik10 = _normalize_cik(raw_digits)
        else:
            ticker_map = _SEC_TICKER_CACHE if own_client else None
            if ticker_map is None:
                tr = safe_http_get(
                    active,
                    "https://www.sec.gov/files/company_tickers.json",
                    headers=headers,
                    rate_limiter=limiter,
                    sleep_fn=sleep_fn,
                )
                tr.raise_for_status()
                raw_map = tr.json()
                ticker_map = {
                    str(entry["ticker"]).upper(): str(entry["cik_str"]).zfill(10)
                    for entry in raw_map.values()
                    if isinstance(entry, dict) and "ticker" in entry and "cik_str" in entry
                }
                if own_client:
                    _SEC_TICKER_CACHE = ticker_map
            if token not in ticker_map:
                raise ValueError(f"Unknown SEC ticker symbol: {token!r}")
            cik10 = ticker_map[token]

        sub_resp = safe_http_get(
            active,
            f"https://data.sec.gov/submissions/CIK{cik10}.json",
            headers=headers,
            rate_limiter=limiter,
            sleep_fn=sleep_fn,
        )
        sub_resp.raise_for_status()
        parsed = _parse_sec_submissions(sub_resp.json(), limit=10)

        facts_resp = safe_http_get(
            active,
            f"https://data.sec.gov/api/xbrl/companyfacts/CIK{cik10}.json",
            headers=headers,
            rate_limiter=limiter,
            sleep_fn=sleep_fn,
        )
        if facts_resp.status_code == 404:
            xbrl_status = "not_available"
            annual: dict[str, Any] = {}
            quarterly: dict[str, Any] = {}
        else:
            facts_resp.raise_for_status()
            structured = extract_sec_financials_from_xbrl(facts_resp.json())
            xbrl_status = "extracted"
            annual = structured["annual"]
            quarterly = structured["quarterly"]

        return {
            "source": "sec_edgar_xbrl",
            "status": "ok",
            "query": ticker_or_cik,
            "cik": parsed["cik"],
            "entity_name": parsed["entity_name"],
            "tickers": parsed["tickers"],
            "exchanges": parsed["exchanges"],
            "sic": parsed["sic"],
            "sic_description": parsed["sic_description"],
            "fiscal_year_end": parsed["fiscal_year_end"],
            "xbrl_status": xbrl_status,
            "annual_financials": annual,
            "quarterly_financials": quarterly,
            "recent_filings": parsed["recent_filings"],
        }
    finally:
        if own_client:
            active.close()


# ---------------------------------------------------------------------------
# Tool 2: sec_form_d_funding_search
# ---------------------------------------------------------------------------


def _validate_iso_date(raw_date: str | None, field_name: str) -> str | None:
    if raw_date is None or not str(raw_date).strip():
        return None
    cleaned = str(raw_date).strip()
    if not _ISO_DATE_RE.match(cleaned):
        raise ValueError(f"Parameter '{field_name}' must use YYYY-MM-DD format, got: {raw_date!r}")
    date.fromisoformat(cleaned)
    return cleaned


def _parse_efts_hits(payload: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    hits_obj = payload.get("hits") if isinstance(payload, dict) else {}
    total_obj = hits_obj.get("total") if isinstance(hits_obj, dict) else {}
    total_hits = int(total_obj.get("value") or 0) if isinstance(total_obj, dict) else 0
    raw_hits = hits_obj.get("hits") if isinstance(hits_obj, dict) else []
    if not isinstance(raw_hits, list):
        raw_hits = []

    records: list[dict[str, Any]] = []
    for hit in raw_hits:
        if not isinstance(hit, dict):
            continue
        src = hit.get("_source") if isinstance(hit.get("_source"), dict) else {}
        hit_id = str(hit.get("_id") or "")
        primary_doc = hit_id.split(":", 1)[1] if ":" in hit_id else ""

        ciks = [
            str(c).zfill(10)
            for c in (src.get("ciks") or [])
            if str(c).strip().isdigit()
        ]
        display_names = [
            str(n).strip() for n in (src.get("display_names") or []) if str(n).strip()
        ]
        entity_name = ""
        if display_names:
            entity_name = re.sub(r"\s*\(CIK\s*\d+\)\s*$", "", display_names[0]).strip()

        adsh = str(src.get("adsh") or "").strip()
        if not adsh and ":" in hit_id:
            adsh = hit_id.split(":", 1)[0].strip()

        edgar_url = ""
        filing_index_url = ""
        if ciks and adsh:
            cik_num = str(int(ciks[0]))
            adsh_nodash = adsh.replace("-", "")
            filing_index_url = (
                f"https://www.sec.gov/Archives/edgar/data/{cik_num}/{adsh_nodash}/{adsh}-index.htm"
            )
            edgar_url = (
                f"https://www.sec.gov/Archives/edgar/data/{cik_num}/{adsh_nodash}/{primary_doc}"
                if primary_doc
                else filing_index_url
            )

        records.append(
            {
                "entity_name": entity_name or None,
                "form": src.get("form"),
                "file_date": src.get("file_date"),
                "primary_cik": ciks[0] if ciks else None,
                "ciks": ciks,
                "accession_number": adsh or None,
                "biz_locations": src.get("biz_locations") or [],
                "biz_states": src.get("biz_states") or [],
                "inc_states": src.get("inc_states") or [],
                "sics": src.get("sics") or [],
                "items": src.get("items") or [],
                "edgar_url": edgar_url or None,
                "filing_index_url": filing_index_url or None,
            }
        )
    return total_hits, records


def sec_form_d_funding_search(
    query: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    limit: int = 15,
    *,
    contact_email: str | None = None,
    client: httpx.Client | None = None,
    rate_limiter: RateLimiter | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Query official SEC EFTS (`efts.sec.gov/LATEST/search-index`) for Form D startup funding filings."""
    cleaned_query = str(query or "").strip() or None
    cleaned_from = _validate_iso_date(date_from, "date_from")
    cleaned_to = _validate_iso_date(date_to, "date_to")
    target_limit = _clamp_int(limit, default=15, minimum=1, maximum=50, field_name="limit")

    user_agent = build_sec_user_agent(contact_email)
    headers = {"User-Agent": user_agent, "Accept": "application/json"}
    own_client = client is None
    active = client if client is not None else _make_client(user_agent=user_agent)
    if rate_limiter is not None:
        limiter = rate_limiter
    elif own_client:
        limiter = _SEC_RATE_LIMITER
    else:
        limiter = RateLimiter(max_per_second=8.0, sleep_fn=sleep_fn)

    params: dict[str, Any] = {
        "forms": "D,D/A",
        "from": 0,
        "size": target_limit,
    }
    if cleaned_query:
        params["q"] = cleaned_query
    if cleaned_from or cleaned_to:
        params["dateRange"] = "custom"
        if cleaned_from:
            params["startdt"] = cleaned_from
        if cleaned_to:
            params["enddt"] = cleaned_to

    try:
        resp = safe_http_get(
            active,
            "https://efts.sec.gov/LATEST/search-index",
            params=params,
            headers=headers,
            rate_limiter=limiter,
            sleep_fn=sleep_fn,
        )
        resp.raise_for_status()
        total_hits, filings = _parse_efts_hits(resp.json())
        return {
            "source": "sec_efts_form_d",
            "status": "ok",
            "query": cleaned_query,
            "date_from": cleaned_from,
            "date_to": cleaned_to,
            "total_hits": total_hits,
            "returned_count": len(filings[:target_limit]),
            "filings": filings[:target_limit],
        }
    finally:
        if own_client:
            active.close()


# ---------------------------------------------------------------------------
# Tool 3: ats_company_jobs (Greenhouse, Lever, Ashby)
# ---------------------------------------------------------------------------


def _infer_seniority(title: str) -> str | None:
    for level, pattern in _SENIORITY_PATTERNS:
        if pattern.search(title or ""):
            return level
    return None


def _extract_tech_tags(text: str) -> list[str]:
    if not text:
        return []
    found: list[str] = []
    for tag, pattern in _TECH_TAG_PATTERNS:
        if pattern.search(text):
            found.append(tag)
    return found


def _parse_salary_number(token: str) -> float | None:
    cleaned = token.strip().replace(",", "")
    mult = 1.0
    if cleaned.lower().endswith("k"):
        mult = 1000.0
        cleaned = cleaned[:-1]
    try:
        return round(float(cleaned) * mult, 2)
    except ValueError:
        return None


def _extract_salary_from_text(text: str) -> dict[str, Any] | None:
    if not text:
        return None
    match = _SALARY_RANGE_RE.search(text)
    if not match:
        return None
    low = _parse_salary_number(match.group("low"))
    high = _parse_salary_number(match.group("high"))
    if low is None or high is None:
        return None
    if low < 10000 and high < 10000:
        return None
    cur_raw = match.group("cur").strip().upper()
    currency_map = {"$": "USD", "£": "GBP", "€": "EUR"}
    currency = currency_map.get(cur_raw, cur_raw or "USD")
    return {
        "currency": currency,
        "min": min(low, high),
        "max": max(low, high),
        "interval": "yearly",
        "summary": match.group(0).strip(),
    }


def _classify_workplace(
    native_type: str | None,
    is_remote_flag: bool | None,
    location: str,
    title: str,
    description_plain: str,
) -> tuple[str, bool]:
    native = str(native_type or "").strip().lower().replace("-", "").replace("_", "")
    if native == "remote":
        return "remote", True
    if native == "hybrid":
        return "hybrid", False
    if native in ("onsite", "inoffice"):
        return "onsite", False
    if is_remote_flag is True:
        return "remote", True

    loc_title = f"{location} {title}".lower()
    if "hybrid" in loc_title:
        return "hybrid", False
    if re.search(r"\b(?:remote|distributed|work\s+from\s+home|wfh|anywhere)\b", loc_title):
        return "remote", True
    if re.search(r"\b(?:on-?site|in-?office)\b", loc_title):
        return "onsite", False

    desc_body = description_plain[:8000].lower()
    if re.search(r"\bhybrid\b", desc_body):
        return "hybrid", False
    if re.search(r"\b(?:fully\s+remote|100%\s+remote|remote-?first)\b", desc_body):
        return "remote", True
    if re.search(r"\b(?:in-?office|on-?site|in\s+person)\b", desc_body):
        return "onsite", False
    return "unspecified", False


def _normalize_greenhouse_jobs(payload: dict[str, Any], company_slug: str) -> list[dict[str, Any]]:
    raw_jobs = payload.get("jobs") if isinstance(payload, dict) else []
    if not isinstance(raw_jobs, list):
        return []
    jobs: list[dict[str, Any]] = []
    for item in raw_jobs:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "").strip()
        loc_obj = item.get("location") if isinstance(item.get("location"), dict) else {}
        location = str(loc_obj.get("name") or "").strip()
        departments = [
            str(d.get("name")).strip()
            for d in (item.get("departments") or [])
            if isinstance(d, dict) and str(d.get("name") or "").strip()
        ]
        # Greenhouse often HTML-entity-encodes its `content` HTML string.
        raw_content = html.unescape(str(item.get("content") or ""))
        desc_plain = html_to_plain_text(raw_content)

        workplace_type, is_remote = _classify_workplace(
            None, None, location, title, desc_plain
        )
        salary = _extract_salary_from_text(desc_plain)
        tech_tags = _extract_tech_tags(f"{title}\n{desc_plain}")
        excerpt, _ = _trim_text(desc_plain, 450)
        url = str(item.get("absolute_url") or "").strip() or None

        jobs.append(
            {
                "job_id": str(item.get("id") or ""),
                "provider": "greenhouse",
                "company_slug": company_slug,
                "title": title,
                "department": departments[0] if departments else None,
                "team": None,
                "location": location or None,
                "workplace_type": workplace_type,
                "is_remote": is_remote,
                "employment_type": None,
                "seniority": _infer_seniority(title),
                "salary": salary,
                "tech_tags": tech_tags,
                "published_at": item.get("first_published") or item.get("updated_at"),
                "url": url,
                "apply_url": url,
                "description_excerpt": excerpt,
                "_search_blob": f"{title} {' '.join(departments)} {location} {' '.join(tech_tags)} {desc_plain}".lower(),
            }
        )
    return jobs


def _normalize_lever_jobs(payload: Any, company_slug: str) -> list[dict[str, Any]]:
    if not isinstance(payload, list):
        return []
    jobs: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        title = str(item.get("text") or "").strip()
        cats = item.get("categories") if isinstance(item.get("categories"), dict) else {}
        location = str(cats.get("location") or "").strip()
        department = str(cats.get("department") or "").strip() or None
        team = str(cats.get("team") or "").strip() or None
        commitment = str(cats.get("commitment") or "").strip() or None

        desc_parts = [str(item.get("descriptionPlain") or "")]
        for sec in item.get("lists") or []:
            if isinstance(sec, dict):
                desc_parts.append(str(sec.get("text") or ""))
                desc_parts.append(html_to_plain_text(sec.get("content")))
        desc_parts.append(str(item.get("additionalPlain") or ""))
        desc_plain = "\n".join(p.strip() for p in desc_parts if p and p.strip())

        workplace_type, is_remote = _classify_workplace(
            item.get("workplaceType"), None, location, title, desc_plain
        )

        salary: dict[str, Any] | None = None
        sr = item.get("salaryRange")
        if isinstance(sr, dict) and (sr.get("min") is not None or sr.get("max") is not None):
            salary = {
                "currency": sr.get("currency"),
                "min": sr.get("min"),
                "max": sr.get("max"),
                "interval": sr.get("interval"),
                "summary": str(item.get("salaryDescriptionPlain") or "").strip() or None,
            }
        if salary is None:
            salary = _extract_salary_from_text(
                f"{item.get('salaryDescriptionPlain') or ''}\n{desc_plain}"
            )

        created_ms = item.get("createdAt")
        published_at: str | None = None
        if isinstance(created_ms, (int, float)) and created_ms > 0:
            published_at = datetime.fromtimestamp(created_ms / 1000.0, tz=timezone.utc).isoformat()

        tech_tags = _extract_tech_tags(f"{title}\n{desc_plain}")
        excerpt, _ = _trim_text(desc_plain, 450)

        jobs.append(
            {
                "job_id": str(item.get("id") or ""),
                "provider": "lever",
                "company_slug": company_slug,
                "title": title,
                "department": department,
                "team": team,
                "location": location or None,
                "workplace_type": workplace_type,
                "is_remote": is_remote,
                "employment_type": commitment,
                "seniority": _infer_seniority(title),
                "salary": salary,
                "tech_tags": tech_tags,
                "published_at": published_at,
                "url": item.get("hostedUrl"),
                "apply_url": item.get("applyUrl") or item.get("hostedUrl"),
                "description_excerpt": excerpt,
                "_search_blob": f"{title} {department or ''} {team or ''} {location} {' '.join(tech_tags)} {desc_plain}".lower(),
            }
        )
    return jobs


def _extract_ashby_salary(item: dict[str, Any], desc_plain: str) -> dict[str, Any] | None:
    comp = item.get("compensation")
    if isinstance(comp, dict):
        summary = str(
            comp.get("compensationTierSummary")
            or comp.get("scrapeableCompensationSalarySummary")
            or ""
        ).strip()
        for sc in comp.get("summaryComponents") or []:
            if not isinstance(sc, dict):
                continue
            min_v = sc.get("minValue")
            max_v = sc.get("maxValue")
            if min_v is not None or max_v is not None:
                return {
                    "currency": sc.get("currencyCode") or "USD",
                    "min": min_v,
                    "max": max_v,
                    "interval": sc.get("interval") or "yearly",
                    "summary": summary or None,
                }
        if summary:
            parsed = _extract_salary_from_text(summary)
            if parsed is not None:
                return parsed
            return {
                "currency": None,
                "min": None,
                "max": None,
                "interval": None,
                "summary": summary,
            }
    return _extract_salary_from_text(desc_plain)


def _normalize_ashby_jobs(payload: dict[str, Any], company_slug: str) -> list[dict[str, Any]]:
    raw_jobs = payload.get("jobs") if isinstance(payload, dict) else []
    if not isinstance(raw_jobs, list):
        return []
    jobs: list[dict[str, Any]] = []
    for item in raw_jobs:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "").strip()
        location = str(item.get("location") or "").strip()
        department = str(item.get("department") or "").strip() or None
        team = str(item.get("team") or "").strip() or None
        desc_plain = str(item.get("descriptionPlain") or "").strip()
        if not desc_plain and item.get("descriptionHtml"):
            desc_plain = html_to_plain_text(item.get("descriptionHtml"))

        workplace_type, is_remote = _classify_workplace(
            item.get("workplaceType"),
            item.get("isRemote") if isinstance(item.get("isRemote"), bool) else None,
            location,
            title,
            desc_plain,
        )
        salary = _extract_ashby_salary(item, desc_plain)
        tech_tags = _extract_tech_tags(f"{title}\n{desc_plain}")
        excerpt, _ = _trim_text(desc_plain, 450)

        jobs.append(
            {
                "job_id": str(item.get("id") or ""),
                "provider": "ashby",
                "company_slug": company_slug,
                "title": title,
                "department": department,
                "team": team,
                "location": location or None,
                "workplace_type": workplace_type,
                "is_remote": is_remote,
                "employment_type": item.get("employmentType"),
                "seniority": _infer_seniority(title),
                "salary": salary,
                "tech_tags": tech_tags,
                "published_at": item.get("publishedAt"),
                "url": item.get("jobUrl"),
                "apply_url": item.get("applyUrl") or item.get("jobUrl"),
                "description_excerpt": excerpt,
                "_search_blob": f"{title} {department or ''} {team or ''} {location} {' '.join(tech_tags)} {desc_plain}".lower(),
            }
        )
    return jobs


def ats_company_jobs(
    provider: str,
    company_slug: str,
    remote_only: bool = False,
    keyword: str | None = None,
    limit: int = 25,
    *,
    client: httpx.Client | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Fetch normalized public jobs from official Greenhouse, Lever, or Ashby JSON APIs."""
    prov = str(provider or "").strip().lower()
    if prov not in _ATS_PROVIDERS:
        raise ValueError(
            f"Unsupported ATS provider {provider!r}. Expected one of: greenhouse, lever, ashby."
        )
    slug = str(company_slug or "").strip()
    if not slug or not _SLUG_RE.match(slug) or ".." in slug:
        raise ValueError(f"Invalid company_slug: {company_slug!r}")

    target_limit = _clamp_int(limit, default=25, minimum=1, maximum=100, field_name="limit")
    needle = str(keyword or "").strip().lower()

    if prov == "greenhouse":
        endpoint = f"https://boards-api.greenhouse.io/v1/boards/{slug}/jobs"
        params: dict[str, Any] = {"content": "true"}
    elif prov == "lever":
        endpoint = f"https://api.lever.co/v0/postings/{slug}"
        params = {"mode": "json"}
    else:
        endpoint = f"https://api.ashbyhq.com/posting-api/job-board/{slug}"
        params = {"includeCompensation": "true"}

    own_client = client is None
    active = client if client is not None else _make_client()
    try:
        resp = safe_http_get(active, endpoint, params=params, sleep_fn=sleep_fn)
        if resp.status_code == 404:
            raise ValueError(
                f"Company board '{slug}' was not found on {prov} (HTTP 404)."
            )
        resp.raise_for_status()
        payload = resp.json()

        if prov == "greenhouse":
            all_jobs = _normalize_greenhouse_jobs(payload, slug)
        elif prov == "lever":
            all_jobs = _normalize_lever_jobs(payload, slug)
        else:
            all_jobs = _normalize_ashby_jobs(payload, slug)

        filtered: list[dict[str, Any]] = []
        for job in all_jobs:
            if remote_only and not job["is_remote"]:
                continue
            if needle and needle not in job["_search_blob"]:
                continue
            clean_job = {k: v for k, v in job.items() if not k.startswith("_")}
            filtered.append(clean_job)

        remote_count = sum(1 for j in all_jobs if j["workplace_type"] == "remote")
        hybrid_count = sum(1 for j in all_jobs if j["workplace_type"] == "hybrid")
        onsite_count = sum(1 for j in all_jobs if j["workplace_type"] == "onsite")
        with_salary_count = sum(1 for j in all_jobs if j["salary"] is not None)

        returned = filtered[:target_limit]
        return {
            "source": f"ats_{prov}",
            "status": "ok",
            "provider": prov,
            "company_slug": slug,
            "api_url": endpoint,
            "total_board_jobs": len(all_jobs),
            "matched_count": len(filtered),
            "returned_count": len(returned),
            "summary": {
                "remote_count": remote_count,
                "hybrid_count": hybrid_count,
                "onsite_count": onsite_count,
                "with_salary_count": with_salary_count,
            },
            "jobs": returned,
        }
    finally:
        if own_client:
            active.close()


# ---------------------------------------------------------------------------
# Tool 4: shopify_store_catalog
# ---------------------------------------------------------------------------


def _parse_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def _normalize_tags(raw_tags: Any) -> list[str]:
    if isinstance(raw_tags, list):
        return [str(t).strip() for t in raw_tags if str(t).strip()]
    if isinstance(raw_tags, str):
        return [part.strip() for part in raw_tags.split(",") if part.strip()]
    return []


def _normalize_store_url(raw_url: str) -> str:
    token = str(raw_url or "").strip()
    if not token:
        raise ValueError("Parameter 'store_url' must not be empty.")
    if "://" not in token:
        token = f"https://{token}"
    return assert_safe_public_url(token, preserve_path=False)


def _normalize_shopify_products(
    payload: dict[str, Any],
    store_base: str,
    *,
    collection_handle: str | None = None,
) -> list[dict[str, Any]]:
    raw_products = payload.get("products") if isinstance(payload, dict) else []
    if not isinstance(raw_products, list):
        return []

    records: list[dict[str, Any]] = []
    for p in raw_products:
        if not isinstance(p, dict):
            continue
        raw_variants = p.get("variants") or []
        variants: list[dict[str, Any]] = []
        prices: list[float] = []
        compare_prices: list[float] = []
        discounts: list[float] = []
        skus: list[str] = []
        in_stock = False
        available_count = 0

        for v in raw_variants:
            if not isinstance(v, dict):
                continue
            price = _parse_float(v.get("price"))
            compare_at = _parse_float(v.get("compare_at_price"))
            if compare_at is not None and compare_at <= 0:
                compare_at = None

            discount_pct: float | None = None
            if price is not None:
                prices.append(price)
            if compare_at is not None:
                compare_prices.append(compare_at)
                if price is not None and compare_at > price:
                    discount_pct = round(((compare_at - price) / compare_at) * 100.0, 2)
                    discounts.append(discount_pct)

            sku = str(v.get("sku") or "").strip()
            if sku:
                skus.append(sku)

            avail_raw = v.get("available")
            avail: bool | None = bool(avail_raw) if avail_raw is not None else None
            if avail is True:
                in_stock = True
                available_count += 1

            variants.append(
                {
                    "id": v.get("id"),
                    "title": v.get("title"),
                    "sku": sku or None,
                    "price": price,
                    "compare_at_price": compare_at,
                    "discount_pct": discount_pct,
                    "available": avail,
                    "option1": v.get("option1"),
                    "option2": v.get("option2"),
                    "option3": v.get("option3"),
                }
            )

        images = [
            str(im.get("src")).strip()
            for im in (p.get("images") or [])
            if isinstance(im, dict) and str(im.get("src") or "").strip()
        ]
        handle = str(p.get("handle") or "").strip()
        product_url = f"{store_base}/products/{handle}" if handle else store_base
        desc, _ = _trim_text(html_to_plain_text(p.get("body_html")), 600)

        records.append(
            {
                "product_id": p.get("id"),
                "handle": handle,
                "title": p.get("title"),
                "vendor": p.get("vendor"),
                "product_type": p.get("product_type"),
                "collection_handle": collection_handle,
                "url": product_url,
                "price_min": min(prices) if prices else None,
                "price_max": max(prices) if prices else None,
                "compare_at_price_max": max(compare_prices) if compare_prices else None,
                "max_discount_pct": max(discounts) if discounts else None,
                "in_stock": in_stock,
                "variant_count": len(variants),
                "available_variant_count": available_count,
                "skus": skus,
                "tags": _normalize_tags(p.get("tags")),
                "image_url": images[0] if images else None,
                "description": desc,
                "variants": variants,
                "published_at": p.get("published_at"),
                "updated_at": p.get("updated_at"),
            }
        )
    return records


def _normalize_shopify_collections(payload: dict[str, Any], store_base: str) -> list[dict[str, Any]]:
    raw_collections = payload.get("collections") if isinstance(payload, dict) else []
    if not isinstance(raw_collections, list):
        return []
    out: list[dict[str, Any]] = []
    for col in raw_collections:
        if not isinstance(col, dict):
            continue
        handle = str(col.get("handle") or "").strip()
        out.append(
            {
                "collection_id": col.get("id"),
                "handle": handle,
                "title": col.get("title"),
                "products_count": col.get("products_count"),
                "url": f"{store_base}/collections/{handle}" if handle else store_base,
            }
        )
    return out


def shopify_store_catalog(
    store_url: str,
    limit: int = 25,
    collection_handle: str | None = None,
    *,
    client: httpx.Client | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Fetch public Shopify `/products.json` and `/collections.json` catalog intelligence."""
    base = _normalize_store_url(store_url)
    target_limit = _clamp_int(limit, default=25, minimum=1, maximum=100, field_name="limit")

    cleaned_handle: str | None = None
    if collection_handle is not None and str(collection_handle).strip():
        cleaned_handle = str(collection_handle).strip().strip("/")
        if not _SLUG_RE.match(cleaned_handle) or ".." in cleaned_handle:
            raise ValueError(f"Invalid Shopify collection_handle: {collection_handle!r}")

    products_endpoint = (
        f"{base}/collections/{cleaned_handle}/products.json"
        if cleaned_handle
        else f"{base}/products.json"
    )

    own_client = client is None
    active = client if client is not None else _make_client()
    try:
        prod_resp = safe_http_get(
            active,
            products_endpoint,
            params={"limit": min(target_limit, 250), "page": 1},
            sleep_fn=sleep_fn,
        )
        if prod_resp.status_code == 404:
            raise ValueError(
                f"Public Shopify feed not found at {products_endpoint} (HTTP 404)."
            )
        prod_resp.raise_for_status()
        try:
            prod_payload = prod_resp.json()
        except ValueError as exc:
            raise ValueError(
                f"Endpoint {products_endpoint} did not return valid JSON (likely not a public Shopify store)."
            ) from exc
        if not isinstance(prod_payload, dict) or "products" not in prod_payload:
            raise ValueError(
                f"Unexpected JSON payload from {products_endpoint}: missing 'products' key."
            )

        effective_parsed = urlparse(str(prod_resp.url))
        effective_base = (
            f"{effective_parsed.scheme}://{effective_parsed.netloc}"
            if effective_parsed.scheme and effective_parsed.netloc
            else base
        )
        products = _normalize_shopify_products(
            prod_payload, effective_base, collection_handle=cleaned_handle
        )[:target_limit]

        collections: list[dict[str, Any]] = []
        try:
            col_resp = safe_http_get(
                active,
                f"{effective_base}/collections.json",
                params={"limit": 50, "page": 1},
                sleep_fn=sleep_fn,
            )
            if col_resp.status_code == 200:
                col_payload = col_resp.json()
                if isinstance(col_payload, dict):
                    collections = _normalize_shopify_collections(col_payload, effective_base)
        except SSRFError:
            raise
        except Exception:
            collections = []

        return {
            "source": "shopify_public_json",
            "status": "ok",
            "store_url": effective_base,
            "collection_handle": cleaned_handle,
            "returned_products": len(products),
            "collections_count": len(collections),
            "collections": collections[:25],
            "products": products,
        }
    finally:
        if own_client:
            active.close()


# ---------------------------------------------------------------------------
# Tool 5: substack_public_posts
# ---------------------------------------------------------------------------


def _resolve_substack_base_url(raw_publication: str) -> str:
    token = str(raw_publication or "").strip()
    if not token:
        raise ValueError("Parameter 'publication' must not be empty.")
    if "://" in token:
        return assert_safe_public_url(token, preserve_path=False)

    stripped = token.lstrip("@").strip().strip("/")
    if "." not in stripped and "/" not in stripped and ":" not in stripped:
        if stripped.lower() in {"localhost", "metadata"}:
            raise SSRFError(f"Forbidden local or internal host: {stripped!r}")
        if not _SUBSTACK_HANDLE_RE.match(stripped):
            raise ValueError(f"Invalid Substack publication handle: {raw_publication!r}")
        return assert_safe_public_url(f"https://{stripped.lower()}.substack.com", preserve_path=False)

    return assert_safe_public_url(f"https://{stripped}", preserve_path=False)


def _slug_from_url(url: str) -> str:
    path = urlparse(str(url or "")).path.strip("/")
    if not path:
        return ""
    return path.split("/")[-1].strip().lower()


def _parse_substack_rss(xml_payload: str | bytes, base_url: str) -> list[dict[str, Any]]:
    root = parse_xml_safely(xml_payload)
    channel: ET.Element | None = None
    if _local_name(root.tag) == "channel":
        channel = root
    else:
        for child in root:
            if _local_name(child.tag) == "channel":
                channel = child
                break
    if channel is None:
        return []

    items: list[dict[str, Any]] = []
    for child in channel:
        if _local_name(child.tag) != "item":
            continue
        link = _child_text(child, "link")
        canonical_url = urljoin(base_url, link) if link else ""
        slug = _slug_from_url(canonical_url)
        raw_encoded = _child_text(child, "encoded")
        raw_desc = _child_text(child, "description")
        best_html = raw_encoded if len(raw_encoded) >= len(raw_desc) else raw_desc
        creator = _child_text(child, "creator", "author")
        pub_raw = _child_text(child, "pubdate", "published", "updated")
        dt = _parse_datetime_utc(pub_raw)
        items.append(
            {
                "title": _child_text(child, "title"),
                "subtitle": html_to_plain_text(raw_desc) if raw_encoded and raw_desc else "",
                "slug": slug,
                "canonical_url": canonical_url,
                "post_date": dt.isoformat() if dt else (pub_raw or None),
                "authors": [creator] if creator else [],
                "body_html": best_html,
            }
        )
    return items


def _fetch_substack_rss(
    client: httpx.Client,
    base_url: str,
    *,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    try:
        resp = safe_http_get(
            client,
            f"{base_url}/feed",
            headers={"Accept": "application/rss+xml, application/xml, text/xml;q=0.9"},
            sleep_fn=sleep_fn,
        )
        if resp.status_code != 200:
            return {}, []
        entries = _parse_substack_rss(resp.content, base_url=base_url)
    except SSRFError:
        raise
    except Exception:
        return {}, []

    lookup: dict[str, dict[str, Any]] = {}
    for entry in entries:
        curl = str(entry.get("canonical_url") or "").strip().rstrip("/").lower()
        slug = str(entry.get("slug") or "").strip().lower()
        if curl:
            lookup[curl] = entry
        if slug:
            lookup[slug] = entry
    return lookup, entries


def substack_public_posts(
    publication: str,
    limit: int = 10,
    only_free: bool = False,
    *,
    client: httpx.Client | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Fetch public Substack `/api/v1/archive` + `/feed` clean Markdown, honestly flagging paywalled posts."""
    base_url = _resolve_substack_base_url(publication)
    target_limit = _clamp_int(limit, default=10, minimum=1, maximum=30, field_name="limit")

    own_client = client is None
    active = client if client is not None else _make_client()

    posts: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    effective_base = base_url

    try:
        rss_lookup: dict[str, dict[str, Any]] = {}
        rss_entries: list[dict[str, Any]] = []
        rss_fetched = False
        archive_unavailable = False

        cursor: str | None = None
        offset = 0
        page_size = 12

        for page_idx in range(4):
            if len(posts) >= target_limit:
                break
            params: dict[str, Any] = {"sort": "new", "limit": page_size}
            if cursor:
                params["cursor"] = cursor
            elif offset > 0:
                params["offset"] = offset

            resp = safe_http_get(
                active,
                f"{effective_base}/api/v1/archive",
                params=params,
                headers={"Accept": "application/json"},
                sleep_fn=sleep_fn,
            )
            if page_idx == 0 and resp.status_code == 404:
                archive_unavailable = True
                break
            resp.raise_for_status()

            resp_parsed = urlparse(str(resp.url))
            if resp_parsed.scheme and resp_parsed.netloc:
                effective_base = f"{resp_parsed.scheme}://{resp_parsed.netloc}"

            payload = resp.json()
            next_cursor: str | None = None
            is_cursor_mode = False
            if isinstance(payload, dict) and isinstance(payload.get("posts"), list):
                raw_posts = payload["posts"]
                raw_next = payload.get("nextCursor")
                next_cursor = str(raw_next) if raw_next else None
                is_cursor_mode = True
            elif isinstance(payload, list):
                raw_posts = payload
            else:
                raise ValueError(f"Unexpected Substack archive JSON payload from {resp.url}")

            if not raw_posts:
                break

            if not rss_fetched:
                rss_lookup, rss_entries = _fetch_substack_rss(
                    active, effective_base, sleep_fn=sleep_fn
                )
                rss_fetched = True

            for post in raw_posts:
                if len(posts) >= target_limit:
                    break
                if not isinstance(post, dict):
                    continue
                dedup_key = str(post.get("id") or post.get("slug") or "")
                if dedup_key and dedup_key in seen_keys:
                    continue
                if dedup_key:
                    seen_keys.add(dedup_key)

                audience = str(post.get("audience") or "everyone").strip().lower()
                is_free_public = audience == "everyone"
                if only_free and not is_free_public:
                    continue

                slug = str(post.get("slug") or "").strip()
                canonical_url = str(post.get("canonical_url") or "").strip()
                if not canonical_url and slug:
                    canonical_url = f"{effective_base}/p/{slug}"

                subtitle = str(post.get("subtitle") or post.get("description") or "").strip()
                preview = str(
                    post.get("truncated_body_text") or post.get("description") or subtitle or ""
                ).strip()

                body_html = ""
                source_api = "substack_archive"
                # Strictly lawful: ONLY enrich full body for free public ("everyone") posts.
                if is_free_public:
                    if str(post.get("body_html") or "").strip():
                        body_html = str(post["body_html"]).strip()
                    else:
                        rss_hit = rss_lookup.get(canonical_url.rstrip("/").lower()) or rss_lookup.get(
                            slug.lower()
                        )
                        if rss_hit and str(rss_hit.get("body_html") or "").strip():
                            body_html = str(rss_hit["body_html"]).strip()
                            source_api = "substack_archive+rss"
                        elif slug:
                            try:
                                detail_resp = safe_http_get(
                                    active,
                                    f"{effective_base}/api/v1/posts/{slug}",
                                    headers={"Accept": "application/json"},
                                    sleep_fn=sleep_fn,
                                )
                                if detail_resp.status_code == 200:
                                    detail = detail_resp.json()
                                    if (
                                        isinstance(detail, dict)
                                        and str(detail.get("audience") or audience).strip().lower()
                                        == "everyone"
                                        and str(detail.get("body_html") or "").strip()
                                    ):
                                        body_html = str(detail["body_html"]).strip()
                                        source_api = "substack_archive+post_api"
                            except SSRFError:
                                raise
                            except Exception:
                                pass

                if body_html:
                    full_md = html_to_markdown(body_html)
                    body_md, truncated = _trim_text(full_md, 10000)
                else:
                    body_md, truncated = _trim_text(preview, 2000)

                bylines = post.get("publishedBylines") or []
                authors = [
                    str(b.get("name")).strip()
                    for b in bylines
                    if isinstance(b, dict) and str(b.get("name") or "").strip()
                ]

                posts.append(
                    {
                        "post_id": post.get("id"),
                        "title": str(post.get("title") or "").strip(),
                        "subtitle": subtitle,
                        "slug": slug,
                        "canonical_url": canonical_url,
                        "post_date": post.get("post_date"),
                        "audience": audience,
                        "is_paywalled": not is_free_public,
                        "paywall_status": "free_public" if is_free_public else "paid_preview_only",
                        "authors": authors,
                        "reaction_count": int(post.get("reaction_count") or 0),
                        "comment_count": int(post.get("comment_count") or 0),
                        "word_count": int(post.get("wordcount") or len(re.findall(r"\S+", body_md))),
                        "body_markdown": body_md,
                        "body_truncated": truncated,
                        "source_api": source_api,
                    }
                )

            if is_cursor_mode:
                if not next_cursor:
                    break
                cursor = next_cursor
            else:
                offset += len(raw_posts)
                if len(raw_posts) < page_size:
                    break

        if archive_unavailable:
            if not rss_fetched:
                _, rss_entries = _fetch_substack_rss(active, effective_base, sleep_fn=sleep_fn)
            if not rss_entries:
                raise ValueError(
                    f"Publication {effective_base} does not expose a public Substack archive or RSS /feed."
                )
            for item in rss_entries[:target_limit]:
                full_md = html_to_markdown(item.get("body_html"))
                body_md, truncated = _trim_text(full_md, 10000)
                posts.append(
                    {
                        "post_id": None,
                        "title": item["title"],
                        "subtitle": item["subtitle"],
                        "slug": item["slug"],
                        "canonical_url": item["canonical_url"],
                        "post_date": item["post_date"],
                        "audience": "everyone",
                        "is_paywalled": False,
                        "paywall_status": "rss_public_feed",
                        "authors": item["authors"],
                        "reaction_count": 0,
                        "comment_count": 0,
                        "word_count": len(re.findall(r"\S+", body_md)),
                        "body_markdown": body_md,
                        "body_truncated": truncated,
                        "source_api": "rss_fallback",
                    }
                )

        return {
            "source": "substack_public",
            "status": "ok",
            "publication_url": effective_base,
            "only_free": bool(only_free),
            "returned_count": len(posts),
            "free_count": sum(1 for p in posts if not p["is_paywalled"]),
            "paywalled_preview_count": sum(1 for p in posts if p["is_paywalled"]),
            "posts": posts,
        }
    finally:
        if own_client:
            active.close()


# ---------------------------------------------------------------------------
# Tool 6: podcast_rss_transcripts
# ---------------------------------------------------------------------------


def _parse_timestamp_seconds(raw_ts: str | int | float | None) -> float | None:
    if raw_ts is None or isinstance(raw_ts, bool):
        return None
    if isinstance(raw_ts, (int, float)):
        val = float(raw_ts)
        return round(val, 3) if math.isfinite(val) and val >= 0.0 else None
    text = str(raw_ts).strip()
    if not text:
        return None
    if text.endswith("s"):
        text = text[:-1].strip()
    try:
        val = float(text)
        return round(val, 3) if math.isfinite(val) and val >= 0.0 else None
    except ValueError:
        pass
    parts = text.replace(",", ".").split(":")
    if len(parts) not in (2, 3):
        return None
    try:
        nums = [float(p) for p in parts]
    except ValueError:
        return None
    if any(not math.isfinite(n) or n < 0.0 for n in nums):
        return None
    total = nums[0] * 60.0 + nums[1] if len(nums) == 2 else nums[0] * 3600.0 + nums[1] * 60.0 + nums[2]
    return round(total, 3)


def _detect_transcript_format(content: str, mime_type: str | None = None, url: str | None = None) -> str:
    mime = (mime_type or "").lower()
    if "json" in mime:
        return "json"
    if "vtt" in mime:
        return "vtt"
    if "srt" in mime or "subrip" in mime:
        return "srt"
    if url:
        path = urlparse(url).path.lower()
        for ext in ("json", "vtt", "srt", "txt"):
            if path.endswith(f".{ext}"):
                return ext
    head = content.lstrip("\ufeff \t\r\n")
    if head.upper().startswith("WEBVTT"):
        return "vtt"
    if head.startswith("{") or head.startswith("["):
        try:
            json.loads(content)
            return "json"
        except json.JSONDecodeError:
            pass
    if "-->" in content[:2000]:
        return "srt"
    return "txt"


def _clean_cue_text(raw_lines: list[str]) -> tuple[str | None, str]:
    joined = " ".join(ln.strip() for ln in raw_lines if ln.strip())
    speaker: str | None = None
    vtt_match = _VTT_SPEAKER_RE.search(joined)
    if vtt_match:
        speaker = vtt_match.group(1).strip() or None
        joined = _VTT_SPEAKER_RE.sub(lambda m: m.group(2), joined)
    plain = html.unescape(_INLINE_TAG_RE.sub("", joined))
    plain = re.sub(r"\s+", " ", plain).strip()
    return speaker, plain


def _parse_vtt_or_srt(content: str, *, is_vtt: bool) -> list[dict[str, Any]]:
    normalized = content.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    blocks = re.split(r"\n\s*\n", normalized.strip())
    segments: list[dict[str, Any]] = []
    for block in blocks:
        lines = [ln for ln in block.splitlines() if ln.strip()]
        if not lines:
            continue
        if is_vtt and lines[0].strip().upper().startswith(("WEBVTT", "NOTE", "STYLE", "REGION")):
            continue
        timing_idx = -1
        timing_match: re.Match[str] | None = None
        for idx, line in enumerate(lines[:2]):
            m = _TIMING_LINE_RE.match(line)
            if m:
                timing_idx = idx
                timing_match = m
                break
        if timing_match is None:
            continue
        speaker, text = _clean_cue_text(lines[timing_idx + 1 :])
        if text:
            segments.append(
                {
                    "start_sec": _parse_timestamp_seconds(timing_match.group(1)),
                    "end_sec": _parse_timestamp_seconds(timing_match.group(2)),
                    "speaker": speaker,
                    "text": text,
                }
            )
    return segments


def _parse_json_transcript(content: str) -> list[dict[str, Any]]:
    payload = json.loads(content.lstrip("\ufeff"))
    raw_segments: list[Any] = []
    if isinstance(payload, list):
        raw_segments = payload
    elif isinstance(payload, dict):
        if isinstance(payload.get("segments"), list):
            raw_segments = payload["segments"]
        elif isinstance(payload.get("cues"), list):
            raw_segments = payload["cues"]
        elif isinstance(payload.get("text"), str) and payload["text"].strip():
            return [
                {
                    "start_sec": None,
                    "end_sec": None,
                    "speaker": None,
                    "text": re.sub(r"\s+", " ", payload["text"]).strip(),
                }
            ]
    segments: list[dict[str, Any]] = []
    for item in raw_segments:
        if not isinstance(item, dict):
            continue
        raw_text = item.get("body") or item.get("text") or item.get("transcript") or ""
        text = re.sub(r"\s+", " ", html.unescape(str(raw_text))).strip()
        if not text:
            continue
        speaker = str(item.get("speaker") or item.get("speakerName") or "").strip() or None
        start_val = item.get("startTime") if "startTime" in item else item.get("start")
        end_val = item.get("endTime") if "endTime" in item else item.get("end")
        segments.append(
            {
                "start_sec": _parse_timestamp_seconds(start_val),
                "end_sec": _parse_timestamp_seconds(end_val),
                "speaker": speaker,
                "text": text,
            }
        )
    return segments


def _parse_txt_transcript(content: str) -> list[dict[str, Any]]:
    normalized = content.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    segments: list[dict[str, Any]] = []
    for line in normalized.splitlines():
        cleaned = line.strip()
        if not cleaned:
            continue
        ts_match = _TXT_TIMESTAMP_LINE_RE.match(cleaned)
        if ts_match:
            start_sec = _parse_timestamp_seconds(ts_match.group(1))
            text = re.sub(r"\s+", " ", ts_match.group(2)).strip()
        else:
            start_sec = None
            text = re.sub(r"\s+", " ", cleaned).strip()
        if text:
            segments.append(
                {"start_sec": start_sec, "end_sec": None, "speaker": None, "text": text}
            )
    return segments


def _normalize_transcript(content: str, mime_type: str | None = None, url: str | None = None) -> dict[str, Any]:
    fmt = _detect_transcript_format(content, mime_type=mime_type, url=url)
    if fmt == "json":
        segments = _parse_json_transcript(content)
    elif fmt == "vtt":
        segments = _parse_vtt_or_srt(content, is_vtt=True)
    elif fmt == "srt":
        segments = _parse_vtt_or_srt(content, is_vtt=False)
    else:
        segments = _parse_txt_transcript(content)

    full_text = re.sub(r"\s+", " ", " ".join(s["text"] for s in segments if s.get("text"))).strip()
    trimmed_text, truncated = _trim_text(full_text, 12000)
    return {
        "format": fmt,
        "segment_count": len(segments),
        "segments": segments[:120],
        "full_transcript": trimmed_text,
        "transcript_truncated": truncated,
    }


def _extract_podcast_channel(channel: ET.Element, feed_url: str) -> dict[str, Any]:
    owner_name: str | None = None
    owner_email: str | None = None
    categories: list[str] = []
    seen_cats: set[str] = set()
    funding_urls: list[str] = []
    people: list[dict[str, Any]] = []

    def _walk_cat(elem: ET.Element) -> None:
        cat_txt = (elem.attrib.get("text") or elem.text or "").strip()
        if cat_txt and cat_txt not in seen_cats:
            seen_cats.add(cat_txt)
            categories.append(cat_txt)
        for sub in elem:
            if _local_name(sub.tag) == "category":
                _walk_cat(sub)

    for child in channel:
        lname = _local_name(child.tag)
        if lname == "owner":
            cand_name = _child_text(child, "name")
            cand_email = _child_text(child, "email")
            if cand_name and not owner_name:
                owner_name = cand_name
            if cand_email and not owner_email:
                owner_email = cand_email
        elif lname == "category":
            _walk_cat(child)
        elif lname == "funding":
            f_url = (child.attrib.get("url") or "").strip()
            if f_url:
                funding_urls.append(urljoin(feed_url, f_url))
        elif lname == "person":
            name = "".join(child.itertext()).strip()
            if name:
                people.append(
                    {
                        "name": name,
                        "role": (child.attrib.get("role") or "").strip() or None,
                    }
                )

    managing_editor = _child_text(channel, "managingeditor")
    if not owner_email and managing_editor:
        match = _EMAIL_SEARCH_RE.search(managing_editor)
        if match:
            owner_email = match.group(0)

    desc, _ = _trim_text(html_to_plain_text(_child_text(channel, "description", "summary")), 800)
    return {
        "feed_url": feed_url,
        "podcast_title": _child_text(channel, "title"),
        "podcast_author": _child_text(channel, "author", "managingeditor") or None,
        "podcast_link": _child_text(channel, "link") or None,
        "language": _child_text(channel, "language") or None,
        "owner_name": owner_name,
        "owner_email": owner_email,
        "categories": categories,
        "funding_urls": funding_urls,
        "people": people,
        "description": desc,
    }


def _resolve_podcast_feed(
    client: httpx.Client,
    query_or_rss_url: str,
    *,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> tuple[str, list[dict[str, Any]]]:
    token = str(query_or_rss_url or "").strip()
    if not token:
        raise ValueError("Parameter 'query_or_rss_url' must not be empty.")

    lower = token.lower()
    if "://" in token:
        parsed = urlparse(token)
        host = (parsed.hostname or "").lower()
        if host.endswith("podcasts.apple.com"):
            apple_match = _APPLE_ID_RE.search(token)
            if not apple_match:
                raise ValueError(f"Could not extract Apple Podcast ID from URL: {token!r}")
            pid = apple_match.group(1)
            resp = safe_http_get(
                client,
                "https://itunes.apple.com/lookup",
                params={"id": pid, "entity": "podcast"},
                sleep_fn=sleep_fn,
            )
            resp.raise_for_status()
            results = (resp.json() or {}).get("results") or []
            for r in results:
                if isinstance(r, dict) and r.get("feedUrl"):
                    return assert_safe_public_url(str(r["feedUrl"])), [
                        {
                            "collection_name": r.get("collectionName"),
                            "artist_name": r.get("artistName"),
                            "feed_url": r.get("feedUrl"),
                            "itunes_id": r.get("collectionId"),
                        }
                    ]
            raise ValueError(f"No public RSS feedUrl found for Apple Podcast ID {pid}.")
        return assert_safe_public_url(token, preserve_path=True), []

    apple_match = _APPLE_ID_RE.match(token)
    if token.isdigit() and len(token) >= 5:
        pid = token
    elif apple_match:
        pid = apple_match.group(1)
    else:
        pid = ""

    if pid:
        resp = safe_http_get(
            client,
            "https://itunes.apple.com/lookup",
            params={"id": pid, "entity": "podcast"},
            sleep_fn=sleep_fn,
        )
        resp.raise_for_status()
        results = (resp.json() or {}).get("results") or []
        for r in results:
            if isinstance(r, dict) and r.get("feedUrl"):
                return assert_safe_public_url(str(r["feedUrl"])), [
                    {
                        "collection_name": r.get("collectionName"),
                        "artist_name": r.get("artistName"),
                        "feed_url": r.get("feedUrl"),
                        "itunes_id": r.get("collectionId"),
                    }
                ]
        raise ValueError(f"No public RSS feedUrl found for Apple Podcast ID {pid}.")

    if lower.startswith(("file:", "ftp:", "gopher:")):
        raise SSRFError(f"Unsupported or invalid HTTP(S) URL: {token!r}")

    resp = safe_http_get(
        client,
        "https://itunes.apple.com/search",
        params={"term": token, "media": "podcast", "entity": "podcast", "limit": 5},
        sleep_fn=sleep_fn,
    )
    resp.raise_for_status()
    results = (resp.json() or {}).get("results") or []
    matched_shows: list[dict[str, Any]] = []
    chosen_feed: str | None = None
    for r in results:
        if not isinstance(r, dict) or not r.get("feedUrl"):
            continue
        feed_url = str(r["feedUrl"]).strip()
        matched_shows.append(
            {
                "collection_name": r.get("collectionName"),
                "artist_name": r.get("artistName"),
                "feed_url": feed_url,
                "itunes_id": r.get("collectionId"),
                "primary_genre": r.get("primaryGenreName"),
            }
        )
        if chosen_feed is None:
            chosen_feed = assert_safe_public_url(feed_url, preserve_path=True)

    if chosen_feed is None:
        raise ValueError(f"No public podcast RSS feed found via Apple iTunes search for: {token!r}")
    return chosen_feed, matched_shows


def podcast_rss_transcripts(
    query_or_rss_url: str,
    limit: int = 5,
    *,
    client: httpx.Client | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Resolve Apple iTunes / Podcasting 2.0 RSS feed, extract host emails & VTT/SRT/JSON transcripts."""
    target_limit = _clamp_int(limit, default=5, minimum=1, maximum=20, field_name="limit")

    own_client = client is None
    active = client if client is not None else _make_client()

    try:
        feed_url, matched_shows = _resolve_podcast_feed(
            active, query_or_rss_url, sleep_fn=sleep_fn
        )
        rss_resp = safe_http_get(
            active,
            feed_url,
            headers={"Accept": "application/rss+xml, application/xml, text/xml;q=0.9, */*;q=0.8"},
            sleep_fn=sleep_fn,
        )
        rss_resp.raise_for_status()

        root = parse_xml_safely(rss_resp.content)
        channel: ET.Element | None = None
        if _local_name(root.tag) == "channel":
            channel = root
        else:
            for child in root:
                if _local_name(child.tag) == "channel":
                    channel = child
                    break
        if channel is None:
            raise ValueError(f"RSS <channel> element not found in feed: {feed_url}")

        channel_meta = _extract_podcast_channel(channel, feed_url=str(rss_resp.url or feed_url))
        episodes: list[dict[str, Any]] = []

        for child in channel:
            if _local_name(child.tag) != "item":
                continue
            if len(episodes) >= target_limit:
                break

            raw_encoded = _child_text(child, "encoded")
            raw_desc = _child_text(child, "description")
            raw_summary = _child_text(child, "summary")
            best_notes = max((raw_encoded, raw_desc, raw_summary), key=len)
            show_notes, _ = _trim_text(html_to_plain_text(best_notes), 700)

            audio_url: str | None = None
            transcript_candidates: list[dict[str, Any]] = []
            chapters_url: str | None = None

            for sub in child:
                lname = _local_name(sub.tag)
                if lname == "enclosure" and audio_url is None:
                    enc_url = (sub.attrib.get("url") or "").strip()
                    if enc_url:
                        audio_url = urljoin(feed_url, enc_url)
                elif lname == "transcript":
                    t_url = (sub.attrib.get("url") or "").strip()
                    if t_url:
                        t_type = (sub.attrib.get("type") or "").strip() or None
                        resolved_t = urljoin(feed_url, t_url)
                        inferred = _detect_transcript_format("", mime_type=t_type, url=resolved_t)
                        transcript_candidates.append(
                            {
                                "url": resolved_t,
                                "type": t_type,
                                "language": (sub.attrib.get("language") or "").strip() or None,
                                "_priority": _TRANSCRIPT_FORMAT_PRIORITY.get(inferred, 99),
                            }
                        )
                elif lname == "chapters" and chapters_url is None:
                    c_url = (sub.attrib.get("url") or "").strip()
                    if c_url:
                        chapters_url = urljoin(feed_url, c_url)

            transcript_candidates.sort(key=lambda c: c["_priority"])
            clean_candidates = [
                {k: v for k, v in c.items() if not k.startswith("_")}
                for c in transcript_candidates
            ]

            transcript_status = "not_present_in_rss"
            transcript_payload: dict[str, Any] | None = None
            transcript_error: str | None = None

            for cand in clean_candidates:
                try:
                    t_resp = safe_http_get(
                        active,
                        cand["url"],
                        headers={"Accept": "application/json, text/vtt, text/plain, */*;q=0.8"},
                        sleep_fn=sleep_fn,
                    )
                    t_resp.raise_for_status()
                    parsed_tr = _normalize_transcript(
                        t_resp.text, mime_type=cand.get("type"), url=cand["url"]
                    )
                    parsed_tr["source_url"] = cand["url"]
                    transcript_payload = parsed_tr
                    transcript_status = "extracted"
                    break
                except SSRFError:
                    raise
                except Exception as exc:
                    transcript_status = "fetch_failed"
                    transcript_error = str(exc)

            pub_raw = _child_text(child, "pubdate", "published", "updated")
            dt = _parse_datetime_utc(pub_raw)
            episodes.append(
                {
                    "episode_title": _child_text(child, "title"),
                    "pub_date_iso": dt.isoformat() if dt else (pub_raw or None),
                    "duration": _child_text(child, "duration") or None,
                    "episode_link": _child_text(child, "link") or None,
                    "audio_url": audio_url,
                    "chapters_url": chapters_url,
                    "show_notes": show_notes,
                    "transcript_candidates": clean_candidates,
                    "transcript_status": transcript_status,
                    "transcript": transcript_payload,
                    "transcript_error": transcript_error,
                }
            )

        return {
            "source": "podcast_rss_podcasting20",
            "status": "ok",
            "query": query_or_rss_url,
            "show": channel_meta,
            "matched_shows": matched_shows,
            "returned_episodes": len(episodes),
            "episodes_with_transcript": sum(
                1 for ep in episodes if ep["transcript_status"] == "extracted"
            ),
            "episodes": episodes,
        }
    finally:
        if own_client:
            active.close()


# ---------------------------------------------------------------------------
# Cloud Pay-Per-Event (PPE) Batch Connector (Apify Store `pecopeko~*`)
# ---------------------------------------------------------------------------

APIFY_CLOUD_ACTORS: dict[str, dict[str, str]] = {
    "shopify": {
        "actor_id": "pecopeko~shopify-public-catalog-feed-extractor",
        "store_url": "https://apify.com/pecopeko/shopify-public-catalog-feed-extractor",
        "ppe_rate": "$0.001 / product",
        "summary": "Multi-store Shopify /products.json & /collections.json cloud batch extractor",
    },
    "ats_jobs": {
        "actor_id": "pecopeko~ats-greenhouse-lever-ashby-jobs-extractor",
        "store_url": "https://apify.com/pecopeko/ats-greenhouse-lever-ashby-jobs-extractor",
        "ppe_rate": "$0.001 / job",
        "summary": "Multi-company Greenhouse, Lever & Ashby ATS job board cloud aggregator",
    },
    "substack": {
        "actor_id": "pecopeko~substack-newsletter-posts-extractor",
        "store_url": "https://apify.com/pecopeko/substack-newsletter-posts-extractor",
        "ppe_rate": "$0.001 / post",
        "summary": "Multi-publication Substack archive & Markdown cloud batch extractor",
    },
    "podcast": {
        "actor_id": "pecopeko~podcast-rss-transcript-extractor",
        "store_url": "https://apify.com/pecopeko/podcast-rss-transcript-extractor",
        "ppe_rate": "$0.002 / episode & transcript",
        "summary": "Batch Apple iTunes & Podcasting 2.0 VTT/SRT/JSON transcript extractor",
    },
    "sec_edgar": {
        "actor_id": "pecopeko~sec-edgar-8-k-10-k-item-extractor",
        "store_url": "https://apify.com/pecopeko/sec-edgar-8-k-10-k-item-extractor",
        "ppe_rate": "$0.004 / filing",
        "summary": "Batch SEC EDGAR 8-K, 10-K & 10-Q section & XBRL cloud extractor",
    },
    "website_tech_stack": {
        "actor_id": "pecopeko~website-tech-stack-sitemap-extractor",
        "store_url": "https://apify.com/pecopeko/website-tech-stack-sitemap-extractor",
        "ppe_rate": "$0.002 / site",
        "summary": "Batch website technology stack, framework & XML sitemap cloud extractor",
    },
    "jpx_tdnet": {
        "actor_id": "pecopeko~tokyo-stock-exchange-jpx-tdnet-english-extractor",
        "store_url": "https://apify.com/pecopeko/tokyo-stock-exchange-jpx-tdnet-english-extractor",
        "ppe_rate": "$0.003 / record",
        "summary": "Batch Tokyo Stock Exchange (JPX/TDnet) English filings, .T quotes, tick/limit bands & BOJ news",
    },
}


def jpx_tokyo_stock_tdnet_disclosures(
    *,
    ticker: str = "",
    limit: int = 10,
    client: httpx.Client | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Fetch real-time Tokyo Stock Exchange (JPX / TDnet) disclosures in English + live .T quote & limit bands."""
    del sleep_fn
    import unicodedata
    import urllib.parse

    bounded = max(1, min(25, int(limit)))
    tk_clean = unicodedata.normalize("NFKC", str(ticker or "")).strip().upper()
    if tk_clean.endswith(".T"):
        tk_clean = tk_clean[:-2]
    if len(tk_clean) == 5 and tk_clean.endswith("0"):
        tk_clean = tk_clean[:4]

    td_url = (
        f"https://webapi.yanoshin.jp/webapi/tdnet/list/{urllib.parse.quote(tk_clean)}.json?limit={bounded}"
        if tk_clean
        else f"https://webapi.yanoshin.jp/webapi/tdnet/list/recent.json?limit={bounded}"
    )

    own_client = client is None
    active = client if client is not None else httpx.Client(timeout=15.0, follow_redirects=True)
    try:
        r_td = active.get(td_url, headers={"User-Agent": "mcp-public-intel/1.1.0"})
        r_td.raise_for_status()
        td_items = r_td.json().get("items") or []
        disclosures = []
        for item in td_items[:bounded]:
            td = item.get("Tdnet") or {}
            raw_code = str(td.get("company_code") or "")
            code4 = raw_code[:4] if len(raw_code) >= 4 else raw_code
            jp_title = str(td.get("title") or "")
            pdf = str(td.get("document_url") or "")
            if "https://www.release.tdnet.info" in pdf:
                pdf = pdf[pdf.find("https://www.release.tdnet.info"):]
            cat = "CORPORATE_DISCLOSURE"
            for kw, c_name in (
                ("決算短信", "EARNINGS_SUMMARY"),
                ("業績予想", "GUIDANCE_REVISION"),
                ("自己株式", "SHARE_BUYBACK"),
                ("配当", "DIVIDEND_REVISION"),
                ("公開買付", "TENDER_OFFER_TOB"),
                ("株式分割", "STOCK_SPLIT"),
                ("月次", "MONTHLY_KPI"),
            ):
                if kw in jp_title:
                    cat = c_name
                    break
            disclosures.append(
                {
                    "id": td.get("id"),
                    "published_at_jst": td.get("pubdate"),
                    "ticker": code4,
                    "company_name_jp": td.get("company_name"),
                    "event_category": cat,
                    "japanese_title": jp_title,
                    "pdf_url": pdf or None,
                }
            )

        quote_summary = None
        if tk_clean:
            q_url = f"https://query1.finance.yahoo.com/v8/finance/chart/{urllib.parse.quote(tk_clean)}.T?range=5d&interval=1d"
            rq = active.get(q_url, headers={"User-Agent": "Mozilla/5.0"})
            if rq.status_code == 200:
                res_list = (rq.json().get("chart") or {}).get("result") or []
                if res_list:
                    meta = res_list[0].get("meta") or {}
                    quote_summary = {
                        "symbol": f"{tk_clean}.T",
                        "currency": meta.get("currency") or "JPY",
                        "last_price_jpy": meta.get("regularMarketPrice"),
                        "previous_close_jpy": meta.get("chartPreviousClose"),
                    }

        return {
            "query_ticker": tk_clean or "MARKET_WIDE_RECENT",
            "returned_disclosures": len(disclosures),
            "quote": quote_summary,
            "disclosures": disclosures,
            "cloud_batch_actor": APIFY_CLOUD_ACTORS["jpx_tdnet"],
        }
    finally:
        if own_client:
            active.close()


def apify_cloud_batch_extract(
    *,
    extractor: str,
    actor_input: dict[str, Any] | None = None,
    apify_token: str | None = None,
    timeout_secs: int = 120,
    client: httpx.Client | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Execute multi-target cloud batch extraction on Apify Store PPE Actors (`pecopeko~*`)."""
    del sleep_fn
    import os

    key = (extractor or "").strip().lower()
    if key not in APIFY_CLOUD_ACTORS:
        valid = ", ".join(sorted(APIFY_CLOUD_ACTORS.keys()))
        raise ValueError(f"Unsupported extractor '{extractor}'. Choose one of: {valid}")

    spec = APIFY_CLOUD_ACTORS[key]
    token = (apify_token or os.environ.get("APIFY_TOKEN") or "").strip()
    bounded_timeout = max(30, min(300, int(timeout_secs)))

    if not token:
        return {
            "status": "setup_required",
            "extractor": key,
            "actor_id": spec["actor_id"],
            "store_url": spec["store_url"],
            "ppe_rate": spec["ppe_rate"],
            "message": (
                "Set APIFY_TOKEN in your MCP environment (or pass apify_token) to run high-volume "
                "cloud batch extraction, scheduled runs, and dataset exports via Apify Store."
            ),
            "available_cloud_actors": APIFY_CLOUD_ACTORS,
        }

    url = f"https://api.apify.com/v2/acts/{spec['actor_id']}/run-sync-get-dataset-items"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "mcp-public-intel/1.0.0 (+https://github.com/pecopeko/mcp-public-intel)",
    }
    params = {"timeout": str(bounded_timeout), "format": "json"}
    payload_in = dict(actor_input or {})

    own_client = client is None
    active = client if client is not None else httpx.Client(timeout=float(bounded_timeout) + 15.0)
    try:
        resp = active.post(url, params=params, headers=headers, json=payload_in)
        if resp.status_code >= 400:
            raise RuntimeError(
                f"Apify cloud run failed (HTTP {resp.status_code} on {spec['actor_id']}): {resp.text[:300]}"
            )
        items = resp.json()
        if not isinstance(items, list):
            items = [items]
        return {
            "status": "ok",
            "extractor": key,
            "actor_id": spec["actor_id"],
            "store_url": spec["store_url"],
            "ppe_rate": spec["ppe_rate"],
            "returned_items": len(items),
            "items": items,
        }
    finally:
        if own_client:
            active.close()


# ---------------------------------------------------------------------------
# MCP Tool Registry & Dispatcher
# ---------------------------------------------------------------------------


TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "sec_company_financials",
        "description": (
            "Fetch live official SEC EDGAR submissions and ASC 606 XBRL companyfacts for a public "
            "company by ticker or CIK, separating annual 10-K vs quarterly 10-Q revenue, net income, "
            "operating income, cash flow, assets, cash, and shares. Zero API key required."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "ticker_or_cik": {
                    "type": "string",
                    "description": "Stock ticker symbol (e.g. 'AAPL', 'NVDA') or numeric SEC CIK (e.g. '0000320193').",
                },
                "contact_email": {
                    "type": "string",
                    "description": "Optional contact email included in the SEC Fair Access User-Agent header.",
                },
            },
            "required": ["ticker_or_cik"],
            "additionalProperties": False,
        },
    },
    {
        "name": "sec_form_d_funding_search",
        "description": (
            "Search official SEC EDGAR Full-Text Search (efts.sec.gov) for recent Form D and Form D/A "
            "private startup funding & venture capital filings. Zero API key required."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Optional search keyword, sector, or company name (e.g. 'artificial intelligence', 'robotics').",
                },
                "date_from": {
                    "type": "string",
                    "description": "Optional start filing date in YYYY-MM-DD format.",
                },
                "date_to": {
                    "type": "string",
                    "description": "Optional end filing date in YYYY-MM-DD format.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of Form D filings to return (1-50, default 15).",
                    "minimum": 1,
                    "maximum": 50,
                    "default": 15,
                },
            },
            "required": [],
            "additionalProperties": False,
        },
    },
    {
        "name": "ats_company_jobs",
        "description": (
            "Fetch normalized live job openings from official public Greenhouse, Lever, or Ashby "
            "JSON job board APIs with remote/hybrid classification, salary extraction, seniority, "
            "and tech stack tags. Zero API key required."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "enum": ["greenhouse", "lever", "ashby"],
                    "description": "Public ATS provider ('greenhouse', 'lever', or 'ashby').",
                },
                "company_slug": {
                    "type": "string",
                    "description": "Company job board slug (e.g. 'anthropic', 'stripe', 'openai', 'linear').",
                },
                "remote_only": {
                    "type": "boolean",
                    "description": "If true, return only roles classified as remote.",
                    "default": False,
                },
                "keyword": {
                    "type": "string",
                    "description": "Optional case-insensitive filter across title, department, location, tech tags, and description.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of jobs to return (1-100, default 25).",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 25,
                },
            },
            "required": ["provider", "company_slug"],
            "additionalProperties": False,
        },
    },
    {
        "name": "shopify_store_catalog",
        "description": (
            "Fetch public Shopify store catalog feeds (/products.json and /collections.json) with "
            "variants, min/max prices, compare-at discount percentages, SKUs, and stock status. "
            "Zero API key required."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "store_url": {
                    "type": "string",
                    "description": "Public Shopify store domain or URL (e.g. 'allbirds.com' or 'https://gymshark.com').",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of products to return (1-100, default 25).",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 25,
                },
                "collection_handle": {
                    "type": "string",
                    "description": "Optional collection handle (e.g. 'best-sellers') to scope products.",
                },
            },
            "required": ["store_url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "substack_public_posts",
        "description": (
            "Fetch public Substack publication posts via /api/v1/archive and /feed RSS as clean "
            "Markdown, honestly flagging paywalled posts without bypassing paywalls. Zero API key required."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "publication": {
                    "type": "string",
                    "description": "Substack handle (e.g. 'pragmaticengineer'), subdomain, or custom domain URL.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of posts to return (1-30, default 10).",
                    "minimum": 1,
                    "maximum": 30,
                    "default": 10,
                },
                "only_free": {
                    "type": "boolean",
                    "description": "If true, omit paywalled previews and return only free public posts.",
                    "default": False,
                },
            },
            "required": ["publication"],
            "additionalProperties": False,
        },
    },
    {
        "name": "podcast_rss_transcripts",
        "description": (
            "Resolve a podcast by Apple iTunes search query, Apple Podcast ID/URL, or direct RSS URL "
            "to extract show metadata, host contact emails (<itunes:owner>), and Podcasting 2.0 "
            "VTT/SRT/JSON transcripts. Zero API key required."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query_or_rss_url": {
                    "type": "string",
                    "description": "Podcast search query, Apple Podcasts URL/ID, or direct public RSS feed URL.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of episodes to return (1-20, default 5).",
                    "minimum": 1,
                    "maximum": 20,
                    "default": 5,
                },
            },
            "required": ["query_or_rss_url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "jpx_tokyo_stock_tdnet_disclosures",
        "description": (
            "Fetch real-time Tokyo Stock Exchange (JPX / TDnet) corporate disclosures classified into "
            "English catalyst categories plus live .T JPY stock quote. Zero API key required."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "ticker": {
                    "type": "string",
                    "description": "Optional 4-char JPX stock code (e.g. '7203', '9984', '130A'). Leave empty for market-wide real-time feed.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum disclosures to return (1-25, default 10).",
                    "minimum": 1,
                    "maximum": 25,
                    "default": 10,
                },
            },
            "required": [],
            "additionalProperties": False,
        },
    },
    {
        "name": "apify_cloud_batch_extract",
        "description": (
            "Run high-volume multi-domain cloud batch extraction via Apify Store Pay-Per-Event "
            "Actors (pecopeko~*): multi-store Shopify catalogs, multi-company ATS jobs, Substack "
            "archives, Podcast transcripts, SEC 8-K/10-K filings, Tokyo Stock Exchange (JPX/TDnet) "
            "English filings & limit bands, and website tech stacks."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "extractor": {
                    "type": "string",
                    "enum": [
                        "shopify",
                        "ats_jobs",
                        "substack",
                        "podcast",
                        "sec_edgar",
                        "website_tech_stack",
                        "jpx_tdnet",
                    ],
                    "description": "Target cloud batch extractor family on Apify Store.",
                },
                "actor_input": {
                    "type": "object",
                    "description": "JSON input object forwarded directly to the cloud Actor.",
                },
                "apify_token": {
                    "type": "string",
                    "description": "Optional Apify API token (falls back to APIFY_TOKEN env var).",
                },
                "timeout_secs": {
                    "type": "integer",
                    "description": "Synchronous cloud run timeout in seconds (30-300, default 120).",
                    "minimum": 30,
                    "maximum": 300,
                    "default": 120,
                },
            },
            "required": ["extractor"],
            "additionalProperties": False,
        },
    },
]

TOOL_HANDLERS: dict[str, Callable[..., dict[str, Any]]] = {
    "sec_company_financials": sec_company_financials,
    "sec_form_d_funding_search": sec_form_d_funding_search,
    "ats_company_jobs": ats_company_jobs,
    "shopify_store_catalog": shopify_store_catalog,
    "substack_public_posts": substack_public_posts,
    "podcast_rss_transcripts": podcast_rss_transcripts,
    "jpx_tokyo_stock_tdnet_disclosures": jpx_tokyo_stock_tdnet_disclosures,
    "apify_cloud_batch_extract": apify_cloud_batch_extract,
}


class UnknownToolError(KeyError):
    """Raised when a client invokes an unregistered MCP tool name."""


def dispatch_tool(
    name: str,
    arguments: dict[str, Any] | None = None,
    *,
    client: httpx.Client | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Validate tool name and invoke the corresponding public-intel tool function."""
    handler = TOOL_HANDLERS.get(name)
    if handler is None:
        raise UnknownToolError(f"Unknown tool: {name}")

    args = dict(arguments or {})
    schema = next(t["inputSchema"] for t in TOOL_DEFINITIONS if t["name"] == name)
    allowed_props = set(schema["properties"].keys())
    unknown_args = set(args.keys()) - allowed_props
    if unknown_args:
        bad = ", ".join(sorted(unknown_args))
        raise ValueError(f"Unexpected argument(s) for tool '{name}': {bad}")

    for req in schema.get("required") or []:
        if req not in args or args[req] is None:
            raise ValueError(f"Missing required argument '{req}' for tool '{name}'.")

    return handler(**args, client=client, sleep_fn=sleep_fn)
