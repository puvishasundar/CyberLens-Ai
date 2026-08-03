# trusted_companies.py — CyberLens AI
#
# Curated allowlist of verified official domains for well-known
# organisations, plus logic to:
#
#   1. Recognise a genuine visit/reference to one of them, so the rest of
#      the pipeline can stop penalising completely normal brand behaviour
#      (login pages, "verify your account" copy, security pages, etc.)
#      that generic lexical/keyword models mistake for phishing.
#
#   2. Flag lookalike / impersonation domains that use a well-known brand
#      name WITHOUT being the official domain — these should be treated
#      as MORE suspicious, not less.
#
# Design intent: this list is intentionally small and hand-verified rather
# than auto-generated. A wrong or overly broad entry here creates a blind
# spot attackers can exploit, so only add domains you can verify
# independently (company's own "official site" statement, WHOIS, etc.).
# This module answers a narrow question and is meant to sit ALONGSIDE the
# existing ML/keyword risk scoring, not replace it.

from typing import Optional

from utils import _domain_core

# brand key -> set of *official*, verified registrable domains.
# Subdomains of these (e.g. accounts.google.com, aws.amazon.com) are
# automatically covered by match_trusted_domain()'s suffix check below.
TRUSTED_COMPANIES = {
    'amazon':     {'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.in',
                   'amazon.ca', 'amazon.co.jp', 'a2z.com'},
    'google':     {'google.com', 'google.co.in', 'google.co.uk', 'gmail.com',
                   'youtube.com', 'goog.co', 'gstatic.com'},
    'microsoft':  {'microsoft.com', 'live.com', 'outlook.com', 'office.com',
                   'microsoftonline.com', 'msn.com', 'azure.com', 'msft.net'},
    'openai':     {'openai.com', 'chatgpt.com'},
    'wikipedia':  {'wikipedia.org', 'wikimedia.org', 'wiktionary.org'},
    'apple':      {'apple.com', 'icloud.com'},
    'meta':       {'meta.com', 'facebook.com', 'instagram.com', 'whatsapp.com'},
    'linkedin':   {'linkedin.com'},
    'paypal':     {'paypal.com'},
    'netflix':    {'netflix.com'},
    'anthropic':  {'anthropic.com', 'claude.ai', 'claude.com'},
}

# brand token (as it might appear inside a domain string) -> canonical key.
# Used only to spot "brand name present but domain isn't the real one".
_BRAND_TOKENS = {
    'amazon': 'amazon', 'google': 'google', 'microsoft': 'microsoft',
    'openai': 'openai', 'chatgpt': 'openai', 'wikipedia': 'wikipedia',
    'apple': 'apple', 'facebook': 'meta', 'instagram': 'meta',
    'whatsapp': 'meta', 'linkedin': 'linkedin', 'paypal': 'paypal',
    'netflix': 'netflix', 'anthropic': 'anthropic', 'claude': 'anthropic',
}


def _normalise(domain: str) -> str:
    d = (domain or '').lower().strip()
    if d.startswith('www.'):
        d = d[4:]
    return d


def match_trusted_domain(domain: str) -> Optional[str]:
    """
    Return the canonical brand key if `domain` IS (or is a subdomain of)
    an official domain for a known brand, else None.

    Subdomains are allowed (accounts.google.com -> 'google') but this is a
    strict suffix match on the *registrable* domain, so it correctly
    REJECTS lookalikes such as 'google.com.verify-account.net' (the
    official-looking prefix doesn't make 'verify-account.net' safe) and
    'amazon-security.com' (not a subdomain of amazon.com at all).
    """
    d = _normalise(domain)
    if not d:
        return None
    for brand, official_domains in TRUSTED_COMPANIES.items():
        for off in official_domains:
            if d == off or d.endswith('.' + off):
                return brand
    return None


def detect_brand_impersonation(domain: str) -> Optional[str]:
    """
    Return the brand being impersonated if `domain` contains a well-known
    brand token but is NOT that brand's official domain.

        'amazon-security-verify.com'  -> 'amazon'   (impersonation)
        'micros0ft-support.net'       -> None       (token doesn't match;
                                                       typosquat detection
                                                       for character-level
                                                       tricks is handled
                                                       separately by the
                                                       existing typosquat
                                                       heuristic in utils)
        'amazon.com'                  -> None       (it's the real thing)
    """
    d = _normalise(domain)
    if not d or match_trusted_domain(d):
        return None
    core = _domain_core(d) if d else ''
    haystack = f"{d} {core}"
    for token, brand in _BRAND_TOKENS.items():
        if token in haystack:
            return brand
    return None


def company_name_matches_brand(company_name: str) -> Optional[str]:
    """
    Fuzzy-map free-text company name (as typed into the Company Verifier
    form) to one of our canonical brand keys, so the caller can cross-check
    'the name the user typed' against 'the domain they gave us'.
    """
    name = (company_name or '').lower()
    if not name:
        return None
    for token, brand in _BRAND_TOKENS.items():
        if token in name:
            return brand
    return None
