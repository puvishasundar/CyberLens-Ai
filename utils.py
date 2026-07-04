# utils.py — CyberLens AI
# Shared helpers: keyword lists, heuristics, risk scoring, URL tools

import re
import math
from urllib.parse import urlparse

# ─── Suspicious Keyword Lexicon ─────────────────────────────────────────────────
NEGATION_WORDS = {
    "no",
    "not",
    "never",
    "without",
    "don't",
    "doesn't",
    "isn't",
    "aren't",
    "won't",
    "free",
    "no registration fee",
    "no processing fee",
    "no joining fee",
    "no payment required",
    "we never ask for otp",
    "never share your password with anyone except",
    "official website",
    "official email",
    "verified company",
    "free of cost"
}
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

    # ── NEW: Courier / Customs / Delivery scams ───────────────────────────────
    'customs fee': 5, 'customs charge': 5, 'customs duty': 5,
    'clearance charges': 5, 'clearance fee': 5, 'customs clearance': 5,
    'package held': 5, 'parcel held': 5, 'parcel on hold': 5,
    'package on hold': 5, 'shipment held': 5, 'shipment on hold': 5,
    'delivery failed': 4, 'delivery attempt failed': 5,
    'delivery on hold': 4, 'unable to deliver': 4,
    'package destruction': 5, 'parcel destruction': 5,
    'package will be destroyed': 5, 'shipment destroyed': 5,
    'pay to release': 5, 'pay to collect': 5, 'pay to receive': 5,
    'release fee': 5, 'release charges': 5,
    'refundable fee': 5, 'refundable customs': 5, 'refundable deposit': 4,
    'mandatory fee': 5, 'mandatory customs': 5, 'mandatory charge': 5,
    'courier scam': 5, 'courier fee': 4, 'courier charges': 4,
    'international parcel': 3, 'international package': 3,
    'dhl': 2, 'fedex': 2, 'bluedart': 2, 'ekart': 2, 'india post': 2,
    'track your parcel': 3, 'track your package': 3, 'track your shipment': 3,
    're-delivery': 3, 'reschedule delivery': 3,
    'within 15 minutes': 5, 'within 30 minutes': 5, 'within 10 minutes': 5,
    'within 24 hours': 4, 'within 48 hours': 3,
    'cancel delivery': 5, 'delivery cancelled': 5, 'delivery will be cancelled': 5,
    'return to sender': 3, 'returned to origin': 4,
    'pending customs': 5, 'pending clearance': 5, 'awaiting customs': 4,
    'storage charges': 4, 'warehouse fee': 4, 'holding fee': 4,

    # ── NEW: Banking / financial impersonation scams ──────────────────────────
    'your card is blocked': 5, 'card blocked': 4, 'debit card blocked': 5,
    'credit card blocked': 5, 'card suspended': 4,
    'net banking blocked': 5, 'net banking suspended': 4,
    'upi blocked': 5, 'upi suspended': 4, 'upi limit': 3,
    'bank account frozen': 5, 'account frozen': 5, 'account deactivated': 5,
    'sbi': 2, 'hdfc': 2, 'icici': 2, 'axis bank': 2, 'kotak': 2,
    'rbi': 3, 'rbi notice': 5, 'reserve bank': 3,
    'your loan is approved': 4, 'pre-approved loan': 4, 'instant loan': 4,
    'loan approved': 4, 'loan offer': 3, 'no collateral': 4,
    'low interest loan': 4, 'personal loan approved': 4,
    'credit score': 2, 'cibil score': 3, 'improve cibil': 4,
    'cashback offer': 3, 'reward points expiring': 4, 'redeem points': 3,

    # ── NEW: Investment / trading / crypto scams ──────────────────────────────
    'guaranteed returns': 5, 'guaranteed profit': 5, 'guaranteed 10x': 5,
    'double your money': 5, 'triple your money': 5,
    'risk free investment': 5, 'risk-free investment': 5,
    'high returns': 4, 'high profit': 4, 'daily returns': 4,
    'weekly returns': 4, 'monthly returns': 4,
    'stock tip': 4, 'insider tip': 5, 'sure shot': 5,
    'multibagger': 4, '100x returns': 5, '10x returns': 5,
    'crypto trading': 3, 'crypto investment': 3, 'forex trading': 3,
    'trading signal': 4, 'trading group': 3, 'trading telegram': 4,
    'nft investment': 3, 'defi investment': 3, 'passive income': 3,
    'referral bonus': 3, 'refer and earn': 3, 'join our group': 3,
    'whatsapp group': 2, 'telegram group': 2,
    'sebi registered': 4, 'rbi approved': 5, 'government approved scheme': 5,

    # ── NEW: Romance / social engineering scams ───────────────────────────────
    'gift card': 4, 'itunes gift card': 5, 'google play gift card': 5,
    'amazon gift card': 4, 'steam gift card': 4,
    'send gift card': 5, 'buy gift card': 4, 'gift card code': 5,
    'i love you': 1, 'lonely': 1, 'dating': 1,
    'military officer': 4, 'deployed overseas': 4, 'stranded abroad': 4,
    'emergency money': 4, 'hospital emergency': 4, 'stuck abroad': 4,
    'send money urgently': 5, 'money transfer urgently': 5,
    'western union': 4, 'moneygram': 4, 'hawala': 4,

    # ── NEW: Government / authority impersonation scams ──────────────────────
    'income tax notice': 5, 'income tax department': 4, 'it department': 3,
    'tax refund': 4, 'tds refund': 5, 'gst refund': 4,
    'cybercrime department': 5, 'cyber crime notice': 5,
    'police notice': 5, 'cbi notice': 5, 'enforcement directorate': 5,
    'arrest warrant': 5, 'fir filed': 5, 'legal action': 4,
    'court notice': 5, 'summons': 4, 'legal notice': 4,
    'aadhaar blocked': 5, 'aadhaar suspended': 5, 'aadhaar linked': 3,
    'pan blocked': 5, 'pan suspended': 5, 'pan deactivated': 5,
    'trai': 3, 'trai notice': 5, 'mobile number blocked': 5,
    'sim blocked': 5, 'sim suspended': 4,
    'epfo': 3, 'pf withdrawal': 3, 'pf account': 2,
    'pm yojana': 3, 'government scheme': 2, 'subsidy approved': 4,
    'digital arrest': 5,

    # ── NEW: Extended urgency / time-pressure patterns ────────────────────────
    'last opportunity': 4, 'final notice': 4, 'final warning': 5,
    'do not ignore': 4, 'respond immediately': 4, 'reply immediately': 4,
    'do not delay': 4, 'time sensitive': 3, 'time-sensitive': 3,
    'expires in': 3, 'valid for': 2, 'offer expires': 3,
    'non-payment': 5, 'failure to pay': 5, 'if not paid': 5,
    'penalty': 3, 'fine': 2, 'legal consequences': 5,

    # ── NEW: Social media / OTT / subscription scams ─────────────────────────
    'your netflix': 3, 'netflix account': 3, 'netflix suspended': 4,
    'amazon prime': 2, 'prime account': 2, 'hotstar': 2,
    'instagram account': 2, 'facebook account': 2, 'account hacked': 4,
    'your instagram': 3, 'your facebook': 3,
    'free subscription': 4, 'free premium': 4, 'upgrade free': 4,

    # ── NEW: Health / insurance scams ────────────────────────────────────────
    'insurance claim': 3, 'claim approved': 4, 'claim settlement': 4,
    'policy expired': 4, 'policy lapsed': 4, 'renew immediately': 4,
    'free health checkup': 3, 'free insurance': 4,
    'cashless treatment': 3, 'hospital cashless': 3,
    'covid relief': 4, 'relief fund': 4, 'compensation fund': 4,

    # ── NEW: Additional scam/suspicious keywords (extended list v2) ──────────
    'verify now': 4, 'click below': 3, 'limited time': 3,
    'claim reward': 4, 'claim prize': 4, 'lottery winner': 5,
    'jackpot': 4, 'selected randomly': 4, 'free iphone': 5,
    'crypto reward': 5, 'bitcoin giveaway': 5,
    'investment opportunity': 3, 'work from home earning': 4,
    'captcha typing job': 5, 'release payment': 5,
    'security alert': 3, 'unauthorized login': 4,
    'bank blocked': 5, 'kyc expired': 5,
    'sim blocked': 5, 'identity suspension': 5,
    'verification failed': 4, 'account disabled': 5,
    'government notice': 4, 'income tax department': 4,
    'cyber cell': 4, 'national security': 4,
    'confidential investigation': 5, 'passport blocked': 5,
    'court order': 5, 'case id': 4, 'criminal activity detected': 5,
    'suspicious activity detected': 4,
    'click to verify': 4, 'login immediately': 4, 'verify identity': 4,
    'update banking details': 5, 'reward expires today': 5,
    'gift voucher': 3, 'international lottery': 5,
    'whatsapp hr': 5, 'telegram manager': 5,
    'contact payout officer': 5, 'activation fee': 5,
    'registration charge': 4, 'remote salary': 4, 'overseas placement': 4,
    'free visa': 4, 'free laptop': 4,
    '100% guaranteed': 5, 'risk free investment': 5,
    'instant payout': 5, 'otp sharing': 5,
    'remote access': 4, 'screen sharing': 4,
    'download apk': 5, 'install app': 3,
    'tinyurl': 3, 'bit.ly': 3, 'rebrand.ly': 3,
    'free recharge': 4, 'casino bonus': 4, 'betting reward': 4,
    'adult verification': 5, 'confirm password': 4,
    'wallet unlocked': 4, 'nft reward': 4,
    'airdrop bonus': 4, 'mining income': 4,
    'crypto wallet verification': 5, 'limited seats': 3,
    'emergency alert': 4, 'red notice': 5, 'high priority warning': 4,
    'user verification pending': 4, 'identity mismatch': 5,
    'kyc mismatch': 5, 'banking restriction': 5,
    'card suspended': 5, 'upi blocked': 5,
    'login expired': 4, 'session timeout': 3, 'reactivate now': 5,
    'social media recovery': 4, 'instagram blue tick': 4,
    'youtube monetization reward': 4, 'copyright strike removal': 4,
    'exclusive access': 3, 'vip membership': 3, 'premium unlocked': 4,
    'earn daily': 4, 'fast cash': 4, 'guaranteed selection': 5,
    'document mismatch': 5, 'suspicious transaction': 5,
    'wire transfer pending': 4, 'wire transfer failed': 4,
    'charity donation request': 4, 'humanitarian fund release': 5,
    'un compensation fund': 5, 'foreign inheritance': 5,
    'lucky draw': 4, 'bonus credited': 3, 'exclusive reward': 3,
    # Emotional manipulation / social engineering
    'fear': 2, 'panic': 3, 'last attempt': 5,
    'important notice': 3, 'immediate response required': 5,
    'avoid suspension': 4, 'avoid arrest': 5,
    'secret reward': 4, 'special opportunity': 3,
    'limited access': 3, 'do not ignore': 4,
    'sensitive information': 3, 'strict action': 4,
    'legal escalation': 5, 'final attempt': 5,
    # Suspicious URL/path keyword mentions
    'login-auth': 5, 'secure-update': 5, 'account-verify': 5,
    'wallet-bonus': 5, 'reward-center': 5, 'gift-claim': 5,
    'kyc-update': 4, 'banking-alert': 5, 'security-check': 4,
    'identity-confirm': 5,

    # ── NEW: Legal threat / cybercrime impersonation language ─────────────────
    'money laundering': 5, 'money laundering investigation': 5,
    'illegal transaction': 5, 'illegal transactions': 5,
    'illegal international': 5, 'fraudulent transaction': 5,
    'section 66': 5, 'section 66c': 5, 'section 66d': 5,
    'it act': 4, 'information technology act': 4,
    'legal complaint': 5, 'complaint filed': 5, 'complaint initiated': 5,
    'case status': 4, 'case active': 5, 'case registered': 5,
    'arrest approval': 5, 'arrest pending': 5, 'immediate arrest': 5,
    'police action': 5, 'police will': 5, 'avoid police': 5,
    'immediate escalation': 5, 'stop escalation': 5,
    'biometric verification': 5, 'identity verification required': 4,
    'account freeze': 5, 'bank account freeze': 5, 'freeze account': 5,
    'passport blacklist': 5, 'blacklisted': 4, 'blacklist': 4,
    'pan card suspension': 5, 'pan suspended': 5, 'pan deactivated': 5,
    'financial monitoring': 5, 'monitoring enabled': 4,
    'fir registration': 5, 'fir will be': 5, 'fir filed against': 5,
    'new delhi': 2, 'cyber crime investigation': 5,
    'national cyber': 5, 'cyber emergency': 5,
    'respond within': 4, 'failure to respond': 5,
    'within 20 minutes': 5, 'within 1 hour': 4,

    # ── NEW: Fake job / overseas employment scam language ─────────────────────
    'approved without interview': 5, 'selected without interview': 5,
    'no interview required': 5, 'direct approval': 4,
    'overseas job': 4, 'overseas remote': 4, 'overseas opportunity': 4,
    'international hiring': 5, 'international hiring database': 5,
    'employee activation': 5, 'activate now': 4, 'activate immediately': 5,
    'offer letter fee': 5, 'receive offer letter': 4,
    'laptop shipment': 4, 'laptop will be sent': 4, 'free laptop': 4,
    'whatsapp hr': 4, 'contact hr on whatsapp': 5,
    'hr manager whatsapp': 5, 'whatsapp number': 3,
    'digital operations': 3, 'remote selection': 4,
    'name will be removed': 5, 'permanently remove': 5, 'removed from database': 5,
    'salary package': 3, 'monthly salary': 2, 'ctc': 2,
    'shortlisted': 3, 'resume shortlisted': 4, 'profile shortlisted': 4,
    'hiring database': 5, 'global hiring': 3,
    'activate today': 4, 'activate your account today': 4,
    'overseas salary': 4, 'foreign salary': 4,
}


# ─── Safe / Legit Keyword Whitelist ─────────────────────────────────────────────
# These words reduce suspicion when found — typical in genuine communication

SAFE_KEYWORDS = {
    'meeting', 'schedule', 'rescheduled', 'project', 'assignment', 'submission',
    'report', 'presentation', 'seminar', 'internship', 'interview',
    'google meet', 'zoom', 'official portal', 'documentation', 'receipt',
    'invoice', 'attached', 'reference', 'confirmation', 'registration',
    'support ticket', 'help desk', 'customer care', 'feedback',
    'guidelines', 'instructions', 'syllabus', 'department', 'university',
    'classroom', 'faculty', 'staff', 'candidate', 'resume', 'application',
    'review process', 'verification completed', 'payment received',
    'tracking number', 'shipment update', 'delivery update',
    'thank you', 'please review', 'attached file', 'agenda', 'discussion',
    'conference', 'deadline reminder', 'orientation', 'offer discussion',
    'training session', 'account statement', 'billing cycle',
    'subscription renewal', 'maintenance notice', 'service update',
    'employee id', 'attendance', 'timesheet', 'workspace', 'portal access',
    'secure login', 'multi-factor authentication', 'official communication',
    'student portal', 'exam hall', 'library', 'lab session',
    'internal marks', 'event registration', 'hackathon', 'technical symposium',
    'job application', 'career portal', 'placement cell', 'team meeting',
    'mentor', 'coordinator', 'faculty advisor', 'hr department',
    'salary credited', 'bank statement', 'otp for login', 'account secured',
    'privacy policy', 'community guidelines', 'customer satisfaction',
    'invoice copy', 'shipment tracking', 'courier update',
    'successful transaction', 'payment confirmation', 'document uploaded',
    'application accepted', 'technical support', 'software update',
    'version release', 'maintenance scheduled', 'ticket resolved',
    'support request', 'video call', 'call scheduled', 'appointment confirmed',
    'delivery expected', 'system generated mail', 'authentication successful',
    'welcome aboard', 'employee onboarding', 'coding round',
    'assessment test', 'interview slot', 'review pending', 'workshop',
    'certificate', 'congratulations on selection', 'campus drive',
    'team collaboration',"no registration fee","no processing fee","no joining fee",
    "no payment required",
    "no advance payment",
    "no security deposit",
    "no hidden charges",
    "we never ask for otp",
    "never ask for otp",
    "never share your otp",
    "official website",
    "official email",
    "official company website","free of cost"
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
    text_lower = text.lower()

    # Remove safe phrases first
    for phrase in SAFE_PHRASES:
        text_lower = text_lower.replace(phrase, "")

    found = {}
    total = 0

    for kw, weight in SCAM_KEYWORDS.items():

        for match in re.finditer(re.escape(kw), text_lower):

            # Look 4 words before keyword
            before = text_lower[max(0, match.start()-35):match.start()]

            words = before.split()

            # Ignore if negation exists
            if any(word in NEGATION_WORDS for word in words):
                continue

            found[kw] = weight
            total += weight

    # -----------------------------
    # Bonus scoring for combinations
    # -----------------------------

    combos = [

        (["registration fee", "urgent"], 3),

        (["registration fee", "immediately"], 3),

        (["otp", "bank"], 4),

        (["lottery", "claim"], 4),

        (["kyc", "account blocked"], 5),

        (["offer letter", "fee"], 5),

        (["click here", "verify"], 4),

        (["bitcoin", "investment"], 5),

        (["work from home", "guaranteed"], 4),

        (["gift card", "send"], 5)

    ]

    for keywords, bonus in combos:
        if all(k in text_lower for k in keywords):
            total += bonus

    return {
        "score": total,
        "found": list(found.keys()),
        "details": found,
    }

def compute_risk_level(score: float) -> dict:
    if score >= 81:
        return {'level': 'CRITICAL', 'color': '#ef4444', 'emoji': '🔴'}
    elif score >= 61:
        return {'level': 'HIGH',     'color': '#f59e0b', 'emoji': '🟠'}
    elif score >= 41:
        return {'level': 'MEDIUM',   'color': '#f59e0b', 'emoji': '🟡'}
    elif score >= 21:
        return {'level': 'LOW',      'color': '#3b82f6', 'emoji': '🔵'}
    else:
        return {'level': 'SAFE',     'color': '#10b981', 'emoji': '🟢'}

def normalise_score(raw: float, ceiling: float = 20.0) -> float:
    """Map a raw keyword score (0 → ceiling+) to 0–100 linearly.
    Ceiling = 20: calibrated against real-world scam messages which score 15–29 raw.
    Linear mapping keeps the output intuitive and predictable.
    Scores above ceiling are capped at 100.
    """
    return round(min(raw / ceiling, 1.0) * 100, 1)

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
