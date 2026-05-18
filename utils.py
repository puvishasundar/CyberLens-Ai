# utils.py — CyberLens AI
# Shared helpers: keyword lists, heuristics, risk scoring, URL tools

import re
import math
from urllib.parse import urlparse

# ─── Suspicious Keyword Lexicon ─────────────────────────────────────────────────

SCAM_KEYWORDS = {
    # Urgency / pressure
    'urgent': 3, 'immediate': 3, 'immediately': 3, 'limited offer': 3,
    'act now': 3, 'expiring': 2, 'deadline': 2, 'last chance': 3,
    'hurry': 2, 'asap': 2, 'today only': 3,
    # Money / payment
    'payment required': 4, 'pay fee': 4, 'registration fee': 4,
    'processing fee': 4, 'security deposit': 4, 'wire transfer': 4,
    'bitcoin': 3, 'crypto payment': 4, 'zelle': 3, 'paypal': 2,
    'advance payment': 4, 'deposit': 3, 'invest': 2, 'guaranteed income': 4,
    'earn guaranteed': 4, 'guaranteed': 3, 'guaranteed placement': 4,
    # Unrealistic promises
    'earn $5000': 4, 'earn $3000': 4, 'earn $2000': 3,
    'earn rs 50000': 4, 'earn rs 30000': 3, 'no experience': 3,
    'no interview': 4, 'direct selection': 4, 'no skills': 3,
    'work from home': 1, 'get rich': 4, 'easy money': 4,
    # Credential harvesting
    'send bank details': 5, 'provide ssn': 5, 'share otp': 5,
    'bank account details': 4, 'personal documents': 3,
    'mother maiden name': 5, 'share documents': 3,
    # Phishing
    'click here': 2, 'verify your account': 3, 'confirm your account': 3,
    'your account is': 2, 'login to verify': 3, 'enter your password': 4,
    'reset your password': 2, 'suspicious activity': 1,
    # ── NEW: OTP / KYC / Indian cyber fraud patterns ──────────────────────────
    'otp': 3, 'one time password': 4, 'share your otp': 5,
    'kyc update': 4, 'kyc verification': 4, 'complete your kyc': 4,
    'kyc expired': 4, 'aadhaar': 2, 'pan card': 2,
    'send aadhaar': 5, 'send pan': 5,
    # Lottery / prize scams
    'you have won': 4, 'you won': 3, 'lucky winner': 4,
    'claim your prize': 4, 'lottery': 3, 'sweepstakes': 3,
    'congratulations you': 3, 'selected winner': 4,
    # Job / placement scams (India-specific)
    'placement fee': 5, 'joining fee': 5, 'training fee': 4,
    'offer letter fee': 5, 'hr team': 1, 'salary upto': 2,
    'ctc upto': 2, 'package upto': 2, 'dream job': 2,
    # Tech support / impersonation scams
    'your computer': 2, 'virus detected': 4, 'call microsoft': 4,
    'call our toll free': 3, 'your device is': 3,
    'technical support': 2, 'refund processing': 3,
    # Generic pressure / social engineering
    'do not share': 2, 'confidential': 1, 'act immediately': 4,
    'your account will be': 3, 'account suspended': 4,
    'account blocked': 4, 'reactivate': 3,
}

PHISHING_URL_PATTERNS = [
    r'login', r'signin', r'verify', r'secure', r'account', r'update',
    r'confirm', r'banking', r'paypal', r'amazon', r'google', r'microsoft',
    r'apple', r'support', r'help', r'alert', r'notification', r'reset',
]

LEGIT_DOMAINS = {
    'google.com', 'microsoft.com', 'amazon.com', 'linkedin.com',
    'apple.com', 'facebook.com', 'twitter.com', 'github.com',
    'paypal.com', 'naukri.com', 'indeed.com', 'glassdoor.com',
    'infosys.com', 'wipro.com', 'tcs.com', 'hcltech.com',
    'accenture.com', 'ibm.com', 'deloitte.com', 'amazon.in',
    'flipkart.com', 'zoho.com', 'freshworks.com',
}

SCAM_TLD_RISK = {
    '.xyz': 4, '.top': 4, '.click': 4, '.loan': 4, '.work': 3,
    '.pw': 4, '.gq': 4, '.cf': 4, '.tk': 4, '.ml': 3, '.ga': 3,
    '.win': 3, '.bid': 3, '.review': 3, '.country': 3,
}

# ─── Risk Scoring ────────────────────────────────────────────────────────────────

def score_keywords(text: str) -> dict:
    """
    Scan text for suspicious keywords.
    Returns {'score': int, 'found': [str, ...], 'details': {word: weight}}.
    """
    text_lower = text.lower()
    found   = {}
    total   = 0

    for kw, weight in SCAM_KEYWORDS.items():
        if kw in text_lower:
            found[kw] = weight
            total    += weight

    return {
        'score':   total,
        'found':   list(found.keys()),
        'details': found,
    }


def compute_risk_level(score: float) -> dict:
    """
    Map a 0–100 risk score to a threat level label.
    """
    if score >= 85:
        return {'level': 'CRITICAL', 'color': '#ef4444', 'emoji': '🔴'}
    elif score >= 65:
        return {'level': 'HIGH',     'color': '#f59e0b', 'emoji': '🟠'}
    elif score >= 40:
        return {'level': 'MEDIUM',   'color': '#f59e0b', 'emoji': '🟡'}
    elif score >= 20:
        return {'level': 'LOW',      'color': '#3b82f6', 'emoji': '🔵'}
    else:
        return {'level': 'SAFE',     'color': '#10b981', 'emoji': '🟢'}


def normalise_score(raw: float, ceiling: float = 50.0) -> float:
    """Map a raw keyword score (0 → ceiling+) to 0–100 via sigmoid-like curve.
    Ceiling raised from 30 → 50: a real scam text often scores 20–40 in keywords,
    so the old ceiling made moderate threats look like CRITICAL incorrectly.
    """
    ratio = min(raw / ceiling, 1.0)
    # Soft curve: low scores stay low, high scores push toward 100
    curved = ratio ** 0.7   # power < 1 gives a concave curve (early scores matter more)
    return round(curved * 100, 1)


# ─── URL Analysis ────────────────────────────────────────────────────────────────

def analyse_url(url: str) -> dict:
    """
    Heuristic phishing / suspicious URL analysis.
    Returns a rich result dict.
    """
    result = {
        'url':           url,
        'is_https':      False,
        'domain':        '',
        'tld':           '',
        'has_ip':        False,
        'is_long':       False,
        'suspicious_kw': [],
        'tld_risk':      0,
        'is_known_legit':False,
        'typosquat_risk':False,
        'risk_score':    0,
        'risk_level':    {},
        'trust_score':   0,
        'flags':         [],
    }

    # ── Basic parse ──────────────────────────────────────────────────────────────
    url_clean = url.strip()
    if not url_clean.startswith(('http://', 'https://')):
        url_clean = 'http://' + url_clean

    try:
        parsed = urlparse(url_clean)
    except Exception:
        result['flags'].append('Could not parse URL')
        result['risk_score'] = 75
        result['risk_level'] = compute_risk_level(75)
        return result

    result['is_https'] = parsed.scheme == 'https'
    domain             = parsed.netloc.lower().replace('www.', '')
    result['domain']   = domain

    # ── TLD ──────────────────────────────────────────────────────────────────────
    tld_match = re.search(r'\.[a-z]{2,}$', domain)
    tld = tld_match.group(0) if tld_match else ''
    result['tld'] = tld
    result['tld_risk'] = SCAM_TLD_RISK.get(tld, 0)

    # ── IP address as domain ─────────────────────────────────────────────────────
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain.split(':')[0]):
        result['has_ip'] = True
        result['flags'].append('IP address used as domain (high risk)')

    # ── URL length ───────────────────────────────────────────────────────────────
    if len(url) > 75:
        result['is_long'] = True
        result['flags'].append(f'Unusually long URL ({len(url)} chars)')

    # ── Suspicious keywords in URL ───────────────────────────────────────────────
    url_lower = url.lower()
    found_kw  = [p for p in PHISHING_URL_PATTERNS if re.search(p, url_lower)]
    result['suspicious_kw'] = found_kw

    # ── Known legit domain ───────────────────────────────────────────────────────
    result['is_known_legit'] = any(domain.endswith(ld) for ld in LEGIT_DOMAINS)

    # ── Typosquatting rough check ────────────────────────────────────────────────
    for legit in LEGIT_DOMAINS:
        core = legit.split('.')[0]
        if core in domain and not domain.endswith(legit):
            result['typosquat_risk'] = True
            result['flags'].append(f'Possible typosquatting of {legit}')
            break

    # ── Compute risk score ───────────────────────────────────────────────────────
    score = 0
    if not result['is_https']:    score += 25          # HTTP is a strong signal
    if result['has_ip']:          score += 35          # IP domains are almost always malicious
    if result['is_long']:         score += 12
    if result['suspicious_kw']:   score += len(result['suspicious_kw']) * 8   # was 5
    if result['tld_risk']:        score += result['tld_risk'] * 8             # was 6
    if result['typosquat_risk']:  score += 35          # typosquatting is very high risk
    if result['is_known_legit']:  score = max(0, score - 40)

    score = min(score, 100)
    result['risk_score']  = score
    result['risk_level']  = compute_risk_level(score)
    result['trust_score'] = max(0, 100 - score)

    return result


# ─── Recruiter / Company Analysis ────────────────────────────────────────────────

FAKE_RECRUITER_SIGNALS = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
    'rediffmail.com', 'ymail.com', 'mail.com',
]

SUSPICIOUS_COMPANY_WORDS = [
    'overseas', 'international jobs', 'global placement', 'abroad job',
    'guaranteed job', 'visa sponsor', 'no fees', 'direct joining',
    '100% placement', 'assured job',
]

def analyse_recruiter_email(email: str) -> dict:
    """Check if a recruiter email looks suspicious."""
    email  = email.lower().strip()
    domain = email.split('@')[-1] if '@' in email else ''
    risky  = domain in FAKE_RECRUITER_SIGNALS
    return {
        'email':      email,
        'domain':     domain,
        'is_free_mail': risky,
        'risk':       'HIGH' if risky else 'LOW',
        'note': 'Legitimate companies use corporate email domains, not free providers.' if risky else 'Domain looks professional.'
    }


def analyse_company_name(name: str) -> dict:
    """Heuristic check on a company name."""
    name_lower = name.lower()
    matches    = [w for w in SUSPICIOUS_COMPANY_WORDS if w in name_lower]
    score      = min(len(matches) * 20, 80)
    return {
        'name':             name,
        'suspicious_terms': matches,
        'risk_score':       score,
        'risk_level':       compute_risk_level(score),
    }


# ─── Session Stats Helpers ───────────────────────────────────────────────────────

def make_empty_stats() -> dict:
    return {
        'total_scans':    0,
        'threats_found':  0,
        'safe_scans':     0,
        'critical':       0,
        'risk_scores':    [],
        'scan_history':   [],   # list of {'type', 'verdict', 'score', 'ts'}
    }


def update_stats(stats: dict, verdict: str, risk_score: float, scan_type: str) -> dict:
    import datetime
    stats['total_scans'] += 1
    stats['risk_scores'].append(risk_score)

    lvl = compute_risk_level(risk_score)['level']
    if lvl in ('CRITICAL', 'HIGH', 'MEDIUM'):
        stats['threats_found'] += 1
    else:
        stats['safe_scans'] += 1

    if lvl == 'CRITICAL':
        stats['critical'] += 1

    stats['scan_history'].append({
        'type':    scan_type,
        'verdict': verdict,
        'score':   risk_score,
        'level':   lvl,
        'ts':      datetime.datetime.now().strftime('%H:%M:%S'),
    })
    return stats


def avg_risk(stats: dict) -> float:
    scores = stats.get('risk_scores', [])
    if not scores:
        return 0.0
    return round(sum(scores) / len(scores), 1)
