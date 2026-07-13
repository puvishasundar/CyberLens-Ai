# analyzer.py — CyberLens AI
# High-level analysis wrappers used by app.py

import io
import logging
import os
import re
import time
import numpy as np
import pytesseract
import requests
import urllib3
from bs4 import BeautifulSoup

# Disable insecure request warning for verify=False on dodgy domains
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Logging ────────────────────────────────────────────────────────────────────
# Uses the root logging config set up in app.py (logging.basicConfig). If this
# module is ever imported standalone (e.g. in a test script), it still logs to
# the console at INFO level by default.
logger = logging.getLogger("cyberlens.analyzer")

_WIN_TESS = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
if os.name == 'nt':
    pytesseract.pytesseract.tesseract_cmd = _WIN_TESS

from utils import (
    score_keywords, compute_risk_level, normalise_score,
    analyse_url, analyse_recruiter_email, analyse_company_name,
    analyse_email_full, verify_company_identity, _domain_core,
    SCAM_KEYWORDS, SHORTENER_DOMAINS
)
from ml_model import predict as ml_predict, get_feature_importance
from url_model import predict_url as url_ml_predict, get_feature_importance_url
from language_utils import detect_and_translate

_RECS = {
    'CRITICAL': [
        '🚨 Do NOT respond to or engage with this message.',
        '🔒 Never share personal information, bank details, or OTPs.',
        '📢 Report this to cybercrime.gov.in or your local cyber cell.',
        '🗑️  Block and delete the sender immediately.',
        '🔍 Warn others in your network about this scam.',
    ],
    'HIGH': [
        '⚠️  Exercise extreme caution — multiple red flags detected.',
        '🔎 Independently verify the company via official channels.',
        '💳 Never pay any fee to secure a job or internship.',
        '📞 Call the company directly using a number from their official website.',
        '📧 Check if the email domain matches the official company domain.',
    ],
    'MEDIUM': [
        '🧐 Treat with moderate caution — some suspicious elements found.',
        '🔍 Research the company on LinkedIn and Glassdoor.',
        '❓ Ask for an official offer letter on company letterhead.',
        '🏦 Never transfer money without verified paperwork.',
    ],
    'LOW': [
        '✅ Low risk — still perform basic due diligence.',
        '🔍 Cross-check recruiter details on LinkedIn.',
        '📋 Request a formal job description and offer letter.',
    ],
    'SAFE': [
        '✅ Content appears legitimate.',
        '📝 Keep documentation of all communications.',
        '🔒 Always protect your personal information.',
    ],
}

def get_recommendations(level: str) -> list:
    return _RECS.get(level, _RECS['SAFE'])

def analyse_text(text: str) -> dict:
    if not text or not text.strip():
        return {'error': 'No text provided'}

    lang_result   = detect_and_translate(text)
    analysis_text = lang_result['translated_text']

    ml_result    = ml_predict(analysis_text)
    ml_scam_prob = ml_result['probability']

    kw_translated = score_keywords(analysis_text)
    kw_original   = score_keywords(lang_result['original_text'])
    kw_result     = kw_translated if kw_translated['score'] >= kw_original['score'] else kw_original
    kw_raw        = kw_result['score']
    kw_norm       = normalise_score(kw_raw, ceiling=20.0)

    if kw_norm >= 60:
        ml_weight, kw_weight = 0.30, 0.70
    elif kw_norm <= 10:
        ml_weight, kw_weight = 0.70, 0.30
    else:
        ml_weight, kw_weight = 0.45, 0.55

    blended = (ml_scam_prob * 100 * ml_weight) + (kw_norm * kw_weight)
    blended = min(round(blended, 1), 100.0)
    
    risk_info   = compute_risk_level(blended)
    level       = risk_info['level']
    confidence  = round(ml_result['confidence'] * 100, 1)

    top_features = get_feature_importance(text, top_n=8)
    feature_words = [f[0] for f in top_features]

    all_suspicious = list(set(kw_result['found'] + feature_words))[:12]

    top_kw_hits = kw_result['found'][:4]

    if level == 'CRITICAL':
        verdict = (
            f"🚨 This content shows strong indicators of a scam or phishing attempt, "
            f"including: {', '.join(top_kw_hits)}. Do not act on any requests within it."
            if top_kw_hits else
            "🚨 This content shows strong indicators of a scam or phishing attempt based on AI pattern analysis. "
            "Do not act on any requests within it."
        )
    elif level == 'HIGH':
        verdict = (
            f"⚠️ This content shows strong indicators of a scam or phishing attempt, "
            f"such as: {', '.join(top_kw_hits)}. Treat it with serious caution."
            if top_kw_hits else
            "⚠️ This content shows strong indicators of a scam or phishing attempt. Treat it with serious caution."
        )
    elif level == 'MEDIUM':
        verdict = (
            f"🧐 This content contains some suspicious elements worth investigating, "
            f"including: {', '.join(top_kw_hits)}. Verify before taking any action."
            if top_kw_hits else
            "🧐 This content contains some suspicious elements worth investigating. Verify before taking any action."
        )
    elif level == 'LOW':
        verdict = (
            "🔵 Only minor risk factors were identified. This content appears largely legitimate "
            "but still warrants basic verification."
        )
    else:
        verdict = "✅ No major suspicious indicators were detected. This content appears to be safe."

    return {
        'risk_score':       blended,
        'confidence':       confidence,
        'ml_probability':   round(ml_scam_prob * 100, 1),
        'risk_level':       level,
        'risk_color':       risk_info['color'],
        'risk_emoji':       risk_info['emoji'],
        'verdict':          verdict,
        'suspicious_kws':   all_suspicious,
        'keyword_hits':     kw_result['found'],
        'recommendations':  get_recommendations(level),
        'ml_label':         ml_result['label'],
        'scan_type':        'Text Analysis',
        'lang_code':        lang_result['lang_code'],
        'lang_name':        lang_result['lang_name'],
        'lang_native':      lang_result['native_name'],
        'lang_flag':        lang_result['flag'],
        'lang_confidence':  lang_result['confidence'],
        'was_translated':   lang_result['was_translated'],
        'translated_text':  lang_result['translated_text'],
        'original_text':    lang_result['original_text'],
        'translation_method': lang_result['translation_method'],
        'translation_success': lang_result['translation_success'],
        'translation_error': lang_result.get('translation_error'),
    }

SCAM_CONTENT_PHRASES = [
    "congratulations! you won", "congratulations, you won", "you have won",
    "you've won", "claim your prize", "win an iphone", "win a free",
    "registration fee", "processing fee required", "verify your account",
    "update your bank details", "update your payment details",
    "limited time offer", "urgent action required", "click here now",
    "act now", "account has been suspended", "confirm your identity",
    "you have been selected", "free gift", "lottery winner",
    "otp verification required", "bank account blocked", "confirm your password",
    "unusual activity detected", "your account will be closed",
    "enter your upi pin", "scan to receive", "scan qr to receive",
    "accept collect request", "upi id blocked", "upi deactivated",
    "scan and win", "scan to claim", "qr code expired",
    "complete your kyc", "kyc expired", "aadhaar blocked", "pan card suspended",
    "digital arrest", "arrest warrant", "cbi notice", "cyber crime notice",
    "legal action will be taken", "court notice", "fir has been filed",
    "income tax notice", "tds refund", "gst refund",
    "pre-approved loan", "instant loan approved", "guaranteed returns",
    "double your money", "risk free investment", "crypto trading signal",
    "sure shot profit", "multibagger stock",
    "no interview required", "joining fee", "offer letter fee",
    "work from home earning", "captcha typing job", "whatsapp hr",
    "customs clearance fee", "parcel on hold", "pay to release your parcel",
    "delivery failed pay", "package will be destroyed",
    "electricity disconnected tonight", "pay electricity bill immediately",
    "power disconnection notice", "update your meter details",
    "scholarship approved", "scholarship processing fee", "fee waiver offer",
    "pay to confirm your order", "order refund pending", "huge discount today only",
    "mega sale 90% off",
    "this is your son", "emergency accident money", "kidnapped call now",
    "voice message urgent",
    "withdraw your winnings", "refer app earn cash", "spin and win",
    "click and earn daily",
    "call this number for refund", "fake customer care agent",
]

def fetch_via_playwright(url: str, timeout_ms: int = 10000) -> tuple:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                viewport={'width': 1280, 'height': 800}
            )
            page = context.new_page()
            response = page.goto(url, timeout=timeout_ms, wait_until='networkidle')
            html = page.content()
            status = response.status if response else 200
            browser.close()
            return html, status, None
    except Exception as e:
        return None, None, str(e)

def analyse_webpage_content(url: str, timeout: int = 8) -> dict:
    """
    Safely fetch HTML, parses, runs JS execution if needed, checks keywords, 
    and passes extracted text directly to the text scam model.
    """
    result = {
        'fetched':            False,
        'url_used':           url,
        'suspicious_phrases': [],
        'content_snippet':    '',
        'extracted_text':     '',
        'error':              None,
        'text_model_label':       None,
        'text_model_probability': 0.0,
        'extracted_text_len':     0,
        'keyword_score_raw':          0.0,
        'keyword_score_normalised':   0.0,
        'keyword_hits':               [],
        'debug_logs': {
            'http_status': None,
            'response_size': 0,
            'html_size': 0,
            'extracted_text_len': 0,
            'extraction_method': 'None',
            'js_rendering_used': False,
            'reached_text_model': False,
            'text_ml_prob': 0.0,
            'rule_score': 0.0,
            'keyword_score_raw': 0.0,
            'keyword_score_normalised': 0.0,
            'keyword_hits': [],
            'final_hybrid_score': 0.0,
        }
    }

    fetch_url = url.strip()
    if not fetch_url.startswith(('http://', 'https://')):
        fetch_url = 'http://' + fetch_url
    result['url_used'] = fetch_url

    logger.info("[URL Scanner] Step 1/5 — starting fetch for %s", fetch_url)

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }

    html_content = ""
    status_code = None
    extraction_method = "Static HTML + BeautifulSoup"
    js_rendering_used = False

    try:
        resp = requests.get(fetch_url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
        status_code = resp.status_code
        result['debug_logs']['http_status'] = status_code
        result['debug_logs']['response_size'] = len(resp.content)
        result['debug_logs']['html_size'] = len(resp.text)
        logger.info(
            "[URL Scanner] Fetch complete — status=%s response_bytes=%s html_bytes=%s",
            status_code, len(resp.content), len(resp.text),
        )

        is_cloudflare = False
        server_header = resp.headers.get('Server', '').lower()
        if 'cloudflare' in server_header or 'cloudflare' in resp.text.lower() or 'ray id' in resp.text.lower():
            is_cloudflare = True

        if status_code == 403:
            if is_cloudflare:
                result['error'] = "Access blocked by Cloudflare bot protection (HTTP 403)."
            else:
                result['error'] = "Access denied by website server (HTTP 403 Forbidden)."
            logger.warning("[URL Scanner] %s (%s)", result['error'], fetch_url)
        elif status_code == 404:
            result['error'] = "The website was not found (HTTP 404 Not Found)."
            logger.warning("[URL Scanner] %s (%s)", result['error'], fetch_url)
        elif status_code >= 500:
            result['error'] = f"The website server returned an error (HTTP {status_code})."
            logger.warning("[URL Scanner] %s (%s)", result['error'], fetch_url)
        else:
            resp.raise_for_status()
            html_content = resp.text

    except requests.exceptions.Timeout:
        result['error'] = "The website took too long to respond (timeout)."
        logger.warning("[URL Scanner] Timeout fetching %s", fetch_url, exc_info=True)
    except requests.exceptions.SSLError:
        result['error'] = "Could not verify the site's SSL certificate."
        logger.warning("[URL Scanner] SSL error fetching %s", fetch_url, exc_info=True)
    except requests.exceptions.ConnectionError:
        result['error'] = "Could not connect to the website — it may be down, blocking requests, or connection refused."
        logger.warning("[URL Scanner] Connection error fetching %s", fetch_url, exc_info=True)
    except requests.exceptions.HTTPError:
        status = resp.status_code if 'resp' in locals() else '?'
        result['error'] = f"The website returned an error (HTTP {status})."
        logger.warning("[URL Scanner] HTTPError (status=%s) fetching %s", status, fetch_url, exc_info=True)
    except Exception as e:
        result['error'] = f"Unable to fetch this website: {str(e)}"
        logger.error("[URL Scanner] Unexpected error fetching %s: %s", fetch_url, e, exc_info=True)

    visible_text = ""
    if html_content:
        soup = BeautifulSoup(html_content, 'html.parser')
        for tag in soup(['script', 'style', 'noscript', 'head', 'svg', 'iframe']):
            tag.decompose()

        extracted_pieces = []
        if soup.title and soup.title.string:
            extracted_pieces.append(soup.title.string.strip())
        
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc and meta_desc.get('content'):
            extracted_pieces.append(meta_desc.get('content').strip())

        for tag in soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'div', 'span', 'button', 'label', 'li']):
            style = tag.get('style', '')
            if 'display:none' in style.replace(' ', '') or 'visibility:hidden' in style.replace(' ', ''):
                continue
            txt = tag.get_text(strip=True)
            if txt:
                extracted_pieces.append(txt)

        for inp in soup.find_all('input'):
            placeholder = inp.get('placeholder')
            if placeholder:
                extracted_pieces.append(placeholder.strip())
            if inp.get('type') in ['button', 'submit'] and inp.get('value'):
                extracted_pieces.append(inp.get('value').strip())

        for img in soup.find_all('img'):
            alt = img.get('alt')
            if alt:
                extracted_pieces.append(alt.strip())

        visible_text = ' '.join(extracted_pieces)
        visible_text = re.sub(r'\s+', ' ', visible_text).strip()
        logger.info(
            "[URL Scanner] Step 2/5 — static extraction: %d chars of visible text (method=%s)",
            len(visible_text), extraction_method,
        )

        # JS Detection and rendering trigger
        text_len = len(visible_text)
        js_required = False
        if text_len < 150:
            js_required = True
        else:
            html_lower = html_content.lower()
            if 'id="root"' in html_lower or 'id="app"' in html_lower or 'id="__next"' in html_lower or '<app-root>' in html_lower:
                js_required = True

        if js_required or result['error']:
            logger.info(
                "[URL Scanner] JS rendering triggered (js_required=%s, prior_error=%s) — invoking Playwright",
                js_required, result['error'],
            )
            try:
                pw_html, pw_status, pw_err = fetch_via_playwright(fetch_url, timeout_ms=8000)
                if pw_err:
                    logger.warning("[URL Scanner] Playwright reported an error for %s: %s", fetch_url, pw_err)
                if pw_html:
                    html_content = pw_html
                    status_code = pw_status or 200
                    result['error'] = None
                    extraction_method = "Playwright rendering"
                    js_rendering_used = True
                    
                    soup = BeautifulSoup(html_content, 'html.parser')
                    for tag in soup(['script', 'style', 'noscript', 'head', 'svg', 'iframe']):
                        tag.decompose()
                        
                    extracted_pieces = []
                    if soup.title and soup.title.string:
                        extracted_pieces.append(soup.title.string.strip())
                    
                    meta_desc = soup.find('meta', attrs={'name': 'description'})
                    if meta_desc and meta_desc.get('content'):
                        extracted_pieces.append(meta_desc.get('content').strip())

                    for tag in soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'div', 'span', 'button', 'label', 'li']):
                        style = tag.get('style', '')
                        if 'display:none' in style.replace(' ', '') or 'visibility:hidden' in style.replace(' ', ''):
                            continue
                        txt = tag.get_text(strip=True)
                        if txt:
                            extracted_pieces.append(txt)

                    for inp in soup.find_all('input'):
                        placeholder = inp.get('placeholder')
                        if placeholder:
                            extracted_pieces.append(placeholder.strip())
                        if inp.get('type') in ['button', 'submit'] and inp.get('value'):
                            extracted_pieces.append(inp.get('value').strip())

                    for img in soup.find_all('img'):
                        alt = img.get('alt')
                        if alt:
                            extracted_pieces.append(alt.strip())

                    visible_text = ' '.join(extracted_pieces)
                    visible_text = re.sub(r'\s+', ' ', visible_text).strip()
                    logger.info(
                        "[URL Scanner] Playwright re-extraction complete: %d chars of visible text",
                        len(visible_text),
                    )
            except ImportError:
                logger.warning(
                    "[URL Scanner] Playwright is not installed — cannot render JS for %s", fetch_url
                )
                if js_required:
                    result['error'] = "This webpage requires JavaScript rendering. Static HTML contained insufficient content for analysis."
            except Exception as e:
                logger.error(
                    "[URL Scanner] Playwright rendering failed for %s: %s", fetch_url, e, exc_info=True
                )
                if js_required:
                    result['error'] = f"This webpage requires JavaScript rendering, but browser automation failed: {str(e)}"

    if visible_text and len(visible_text.strip()) >= 15:
        visible_lower = visible_text.lower()
        found = [p for p in SCAM_CONTENT_PHRASES if p in visible_lower]

        result['fetched']            = True
        result['suspicious_phrases'] = found
        result['content_snippet']    = visible_text[:500]
        # Fuller copy of the extracted text so the results page can show what
        # was actually scraped from the page (capped to keep the UI/response light).
        result['extracted_text']     = visible_text[:5000]
        result['extracted_text_len'] = len(visible_text)

        logger.info(
            "[URL Scanner] Step 3/5 — %d scam phrase(s) matched against curated phrase list: %s",
            len(found), found[:5],
        )

        # ── Step 4/5: keyword-based scoring, using the SAME score_keywords()
        # function the text scanner (analyse_text) uses, so URL page content
        # and pasted text are scored with identical keyword logic. ──────────
        try:
            kw_result = score_keywords(visible_text)
            kw_raw    = kw_result['score']
            kw_norm   = normalise_score(kw_raw, ceiling=20.0)

            result['keyword_score_raw']        = kw_raw
            result['keyword_score_normalised'] = kw_norm
            result['keyword_hits']             = kw_result['found']

            result['debug_logs']['keyword_score_raw']        = kw_raw
            result['debug_logs']['keyword_score_normalised'] = kw_norm
            result['debug_logs']['keyword_hits']              = kw_result['found']

            logger.info(
                "[URL Scanner] score_keywords() on page text — raw=%s normalised=%s hits=%s",
                kw_raw, kw_norm, kw_result['found'][:8],
            )
        except Exception as e:
            logger.error(
                "[URL Scanner] score_keywords() failed on extracted page text for %s: %s",
                fetch_url, e, exc_info=True,
            )

        # ── Step 5/5: run the extracted text through the text-scam ML model ──
        reached_text_model = False
        text_ml_prob = 0.0
        text_model_label = None
        try:
            text_ml = ml_predict(visible_text[:5000])
            text_model_label = text_ml.get('label')
            text_ml_prob = round(float(text_ml.get('probability', 0.0)), 4)
            result['text_model_label']       = text_model_label
            result['text_model_probability'] = text_ml_prob
            reached_text_model = True
            logger.info(
                "[URL Scanner] Text ML model scored page content — label=%s probability=%s",
                text_model_label, text_ml_prob,
            )
        except Exception as e:
            logger.error(
                "[URL Scanner] Text ML model failed on extracted page text for %s: %s",
                fetch_url, e, exc_info=True,
            )

        result['debug_logs']['reached_text_model'] = reached_text_model
        result['debug_logs']['text_ml_prob'] = text_ml_prob

        # Legacy heuristic rule score — kept alongside score_keywords() for
        # backward-compatible debug output (see 'rule_score' in the debug panel).
        try:
            from ml_model import rule_based_scam_score
            result['debug_logs']['rule_score'] = rule_based_scam_score(visible_text)
        except Exception as e:
            logger.warning(
                "[URL Scanner] rule_based_scam_score() failed for %s: %s", fetch_url, e, exc_info=True
            )
    else:
        logger.info(
            "[URL Scanner] Not enough visible text extracted (%d chars) — skipping keyword/ML content scoring",
            len(visible_text.strip()) if visible_text else 0,
        )

    result['debug_logs']['extracted_text_len'] = len(visible_text)
    result['debug_logs']['extraction_method'] = extraction_method if visible_text else "Failed"
    result['debug_logs']['js_rendering_used'] = js_rendering_used

    return result

def analyse_url_full(url: str) -> dict:
    """Wrap utils.analyse_url with a friendly result envelope."""
    if not url or not url.strip():
        return {'error': 'No URL provided'}

    logger.info("[URL Scanner] ==== New scan requested for: %s ====", url)

    base = analyse_url(url)
    rs   = base['risk_score']
    ri   = base['risk_level']
    logger.info("[URL Scanner] URL heuristic score (analyse_url): %s (%s)", rs, ri)

    indicators = []
    if not base['is_https']:        indicators.append('No HTTPS encryption')
    if base['has_ip']:              indicators.append('IP address as domain')
    if base['is_long']:             indicators.append('Abnormally long URL')
    if base['suspicious_kw']:       indicators.append(f"Phishing keywords: {', '.join(base['suspicious_kw'][:4])}")
    if base['tld_risk']:            indicators.append(f"High-risk TLD: {base['tld']}")
    if base['typosquat_risk']:      indicators.append('Possible typosquatting of known brand')
    if base['is_known_legit']:      indicators.append('Domain matches known legitimate site')

    if '@' in url:
        indicators.append('URL contains suspicious "@" character')
    if '%' in url:
        indicators.append('URL contains percent-encoded characters')
    if any('redirection' in f for f in base['flags']):
        indicators.append('URL contains suspicious redirection parameters')
    if any('entropy' in f for f in base['flags']):
        indicators.append('High string randomness/entropy')

    is_shortened_domain = any(sd in url.lower() for sd in SHORTENER_DOMAINS)
    if is_shortened_domain:
        indicators.append('Masked URL (using known link shortener)')

    content_result = analyse_webpage_content(url)
    scam_phrases    = content_result.get('suspicious_phrases', [])
    if scam_phrases:
        indicators.append(f"Scam phrases found on page: {', '.join(scam_phrases[:4])}")

    content_bonus = min(15 * len(scam_phrases), 45)

    text_ml_prob  = content_result.get('text_model_probability', 0.0) or 0.0
    text_ml_label = content_result.get('text_model_label')
    if content_result.get('fetched') and text_ml_label is not None:
        if text_ml_prob >= 0.5:
            indicators.append(
                f"Webpage text flagged as scam-like by text AI model ({round(text_ml_prob * 100)}% confidence)"
            )
        elif text_ml_prob < 0.35:
            indicators.append("Webpage text rated as likely legitimate by text AI model")
    
    text_ml_bonus = round(text_ml_prob * 35) if content_result.get('fetched') else 0

    url_ml_result = url_ml_predict(url)
    ml_prob       = url_ml_result.get('probability', 0.0)
    ml_fetched    = url_ml_result.get('fetched', False)
    ml_fetch_note = url_ml_result.get('fetch_note')

    try:
        url_ml_top_signals_raw = get_feature_importance_url(url, top_n=5)
        url_ml_top_signals = [name for name, _score in url_ml_top_signals_raw]
        logger.info(
            "[URL Scanner] get_feature_importance_url() top signals for %s: %s",
            url, url_ml_top_signals_raw,
        )
    except Exception as e:
        logger.warning(
            "[URL Scanner] get_feature_importance_url() failed for %s: %s", url, e, exc_info=True
        )
        url_ml_top_signals = []

    if url_ml_result.get('label') != 'unknown':
        if url_ml_result['label'] == 'phishing':
            indicators.append(
                f"AI model flags URL as phishing ({round(ml_prob * 100)}% confidence)"
            )
        else:
            indicators.append("AI model rates URL as likely legitimate")

        ml_bonus = round(ml_prob * (55 if ml_fetched else 40))
    else:
        ml_bonus = 0

    # Redirection check / Shortener suspension check
    shortener_warning_detected = False
    warning_phrases = [
        "created by a suspended account",
        "link has been suspended",
        "why was this link blocked",
        "link has been blocked",
        "flagged as spam, phishing",
        "no longer available because it was created by a suspended account",
        "violates our terms of service",
        "violates our acceptable use policy",
        "site has been suspended",
        "account suspended",
        "this link has been flagged"
    ]
    
    page_text_lower = content_result.get('content_snippet', '').lower()
    is_dest_shortened = any(sd in content_result.get('url_used', '').lower() for sd in SHORTENER_DOMAINS)
    
    if is_shortened_domain or is_dest_shortened:
        if any(p in page_text_lower for p in warning_phrases):
            shortener_warning_detected = True

    false_safe_floor = 0
    if url_ml_result.get('label') == 'phishing' and ml_prob >= 0.75:
        false_safe_floor = 65
    elif url_ml_result.get('label') == 'phishing' and ml_prob >= 0.60:
        false_safe_floor = 45

    if content_result.get('fetched') and text_ml_prob >= 0.80:
        false_safe_floor = max(false_safe_floor, 60)
    elif content_result.get('fetched') and text_ml_prob >= 0.65:
        false_safe_floor = max(false_safe_floor, 40)

    if base['typosquat_risk']:
        false_safe_floor = max(false_safe_floor, 65)
    if base['has_ip'] or '@' in url:
        false_safe_floor = max(false_safe_floor, 55)

    if shortener_warning_detected:
        indicators.append('URL officially suspended/blocked by provider for abuse/phishing')
        false_safe_floor = 90

    final_score = max(min(rs + content_bonus + ml_bonus + text_ml_bonus, 100), false_safe_floor)
    final_ri    = compute_risk_level(final_score)

    indicators = list(dict.fromkeys(indicators))

    # ── Explanation bullets ──────────────────────────────────────────────
    # Built only from signals that actually fed into the risk score above
    # (real keyword hits, real ML flags, real domain/TLD risk) — not a loose
    # re-scan of raw text — so the explanation can never claim "high-risk
    # indicators" when the computed score doesn't reflect that.
    explanation_bullets = []

    if shortener_warning_detected:
        explanation_bullets.append("✓ URL officially suspended/blocked by the provider for abuse")
    if base['suspicious_kw'] or scam_phrases:
        kws_display = list(dict.fromkeys(list(base['suspicious_kw']) + list(scam_phrases)))[:4]
        explanation_bullets.append(f"✓ Suspicious keywords found: {', '.join(kws_display)}")
    if base['tld_risk'] > 0 or base['has_ip'] or base['typosquat_risk'] or '@' in url or is_shortened_domain or is_dest_shortened:
        explanation_bullets.append("✓ Suspicious domain, TLD, or shortened link structure")
    if not base['is_https']:
        explanation_bullets.append("✓ Connection is not secured with HTTPS")
    if (url_ml_result.get('label') == 'phishing' and ml_prob >= 0.5) or (text_ml_prob >= 0.5):
        explanation_bullets.append("✓ Flagged with high confidence by AI threat models")

    # The tone and content of the verdict always matches the FINAL risk
    # level, never the raw presence of a loosely-matched keyword.
    final_level = final_ri['level']
    if final_level == 'CRITICAL':
        if explanation_bullets:
            verdict = "🚨 This URL has been flagged with multiple high-risk indicators:\n\n" + "\n".join(explanation_bullets)
        else:
            verdict = "🚨 This URL shows strong phishing indicators and is likely malicious. Do not enter any personal information."
    elif final_level == 'HIGH':
        if explanation_bullets:
            verdict = "⚠️ This URL shows strong suspicious indicators:\n\n" + "\n".join(explanation_bullets)
        else:
            verdict = "⚠️ This URL shows strong phishing indicators and is likely malicious."
    elif final_level == 'MEDIUM':
        if explanation_bullets:
            verdict = "🧐 This URL has some suspicious characteristics worth investigating:\n\n" + "\n".join(explanation_bullets)
        else:
            verdict = "🧐 This URL has some suspicious characteristics. Exercise caution before proceeding."
    elif final_level == 'LOW':
        if explanation_bullets:
            verdict = "🔵 Only minor risk factors were identified:\n\n" + "\n".join(explanation_bullets)
        else:
            verdict = "🔵 This URL appears mostly safe. Only minor risk factors were identified — basic verification is still recommended."
    else:  # SAFE
        verdict = "✅ No major suspicious indicators were detected. This URL appears to be safe."

    debug_logs = content_result.get('debug_logs', {})
    debug_logs['final_hybrid_score'] = final_score
    debug_logs['url_ml_prob'] = ml_prob
    debug_logs['url_heuristic_score'] = rs
    debug_logs['url_ml_top_signals'] = url_ml_top_signals
    debug_logs['url_ml_fetch_note'] = ml_fetch_note

    logger.info(
        "[URL Scanner] ==== Scan complete for %s — final_score=%s level=%s "
        "url_ml=%s(%.4f) text_ml=%s(%.4f) fetch_note=%s ====",
        url, final_score, final_ri['level'],
        url_ml_result.get('label', 'unknown'), ml_prob,
        content_result.get('text_model_label'), text_ml_prob,
        ml_fetch_note,
    )

    return {
        **base,
        'risk_score':      final_score,
        'risk_level':      final_ri['level'],
        'risk_color':      final_ri['color'],
        'risk_emoji':      final_ri['emoji'],
        'verdict':         verdict,
        'indicators':      indicators,
        'suspicious_kws':  base['suspicious_kw'],
        'recommendations': get_recommendations(final_ri['level']),
        'confidence':      min(95, max(50, int(max(ml_prob, text_ml_prob) * 100))),
        'scan_type':       'URL Scanner',
        'content_analysis':content_result,
        'open_url':        content_result.get('url_used', url),
        'url_ml_label':      url_ml_result.get('label', 'unknown'),
        'url_ml_probability':round(ml_prob * 100, 1),
        'url_ml_fetched':    ml_fetched,
        'url_ml_fetch_error':url_ml_result.get('fetch_error'),
        'url_ml_top_signals':url_ml_top_signals,
        'fetch_note':        ml_fetch_note,
        'text_model_label':       content_result.get('text_model_label'),
        'text_model_probability': round(text_ml_prob * 100, 1),
        'debug_logs':      debug_logs,
    }

# ─── QR content-type detection ──────────────────────────────────────────────
# Recognises the common QR payload shapes (URL, mailto:/bare email, tel:/bare
# phone number) so the QR scanner can route each type to the correct existing
# pipeline instead of guessing with a single loose check.
_EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$')
_PHONE_RE = re.compile(r'^\+?[0-9][0-9\s\-().]{6,18}[0-9]$')

def detect_qr_content_type(data: str) -> str:
    """
    Classify decoded QR payload as one of: URL, EMAIL, PHONE, TEXT.
    Mirrors the QR payload shapes commonly produced by generators:
      - URL:   'http://...', 'https://...', or a bare domain like 'example.com/x'
      - Email: 'mailto:user@domain.com' or a bare email address
      - Phone: 'tel:+1234567890' or a bare phone number
      - Text:  anything else (wifi configs, vCards, plain text, etc.)
    """
    if not data:
        return 'TEXT'

    payload = data.strip()

    # ── URL ──
    if payload.startswith(('http://', 'https://')):
        return 'URL'

    # ── Email ──
    if payload.lower().startswith('mailto:'):
        return 'EMAIL'
    if _EMAIL_RE.match(payload):
        return 'EMAIL'

    # ── Phone ──
    if payload.lower().startswith('tel:'):
        return 'PHONE'
    if _PHONE_RE.match(payload):
        return 'PHONE'

    # ── Bare domain heuristic (no scheme, e.g. "example.com/promo") ──
    first_segment = payload.split('/')[0].split('?')[0]
    if '.' in first_segment and ' ' not in first_segment and '@' not in first_segment:
        # crude but effective TLD-shape check: letters after the last dot
        tld_candidate = first_segment.rsplit('.', 1)[-1]
        if tld_candidate.isalpha() and 2 <= len(tld_candidate) <= 24:
            return 'URL'

    return 'TEXT'


def analyse_qr(image_bytes: bytes) -> dict:
    try:
        import cv2
        from PIL import Image
        import numpy as np

        pil_img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
        cv_img  = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)

        qr_detector = cv2.QRCodeDetector()
        qr_data, bbox, _ = qr_detector.detectAndDecode(cv_img)

        if not qr_data:
            try:
                wechat_detector = cv2.wechat_qrcode_WeChatQRCode()
                texts, _ = wechat_detector.detectAndDecode(cv_img)
                if texts:
                    qr_data = texts[0]
            except Exception:
                pass

        if not qr_data:
            gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
            _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            gray_3ch = cv2.cvtColor(thresh, cv2.COLOR_GRAY2BGR)
            qr_data, bbox, _ = qr_detector.detectAndDecode(gray_3ch)

        if not qr_data:
            return {'error': 'No QR code detected in the image. Please ensure the QR code is clear, well-lit, and not blurry.'}

        # ── Step 1: identify content type (URL / EMAIL / PHONE / TEXT) ──────
        content_type = detect_qr_content_type(qr_data)
        is_url = content_type == 'URL'
        logger.info("[QR Scanner] Decoded payload classified as %s: %r", content_type, qr_data[:120])

        result = {
            'qr_data':      qr_data,
            'qr_type':      content_type,   # kept for backward-compat with existing UI key
            'content_type': content_type,
            'is_url':       is_url,
        }

        # ── Step 2: route to the correct EXISTING pipeline — no duplicate
        # detection logic. URLs go through the full URL scanner pipeline
        # (feature extraction, ML prediction, webpage fetch, text scam
        # detection, combined risk score); everything else (plain text,
        # email address, phone number) goes through the same text-scam
        # detection module used by the Text Scanner. ─────────────────────
        if content_type == 'URL':
            # Normalise bare domains (e.g. "example.com/x") to a fetchable
            # URL before handing off, without altering analyse_url_full()
            # itself — this keeps the URL pipeline the single source of truth.
            target_url = qr_data if qr_data.startswith(('http://', 'https://')) else f'http://{qr_data}'
            url_result = analyse_url_full(target_url)
            result.update(url_result)
        else:
            # For EMAIL / PHONE / TEXT payloads, strip any URI scheme
            # (mailto:/tel:) before handing to the text scam detector so it
            # scores the actual address/number/content, not the scheme noise.
            text_payload = re.sub(r'^(mailto:|tel:)', '', qr_data, flags=re.IGNORECASE).strip()
            text_result = analyse_text(text_payload)
            result.update(text_result)

        result['scan_type'] = 'QR Scanner'
        return result

    except ImportError as e:
        return {'error': f'OpenCV not installed: {e}. Install with: pip install opencv-python-headless'}
    except Exception as e:
        return {'error': f'QR analysis failed: {str(e)}'}

def analyse_ocr_image(image_bytes: bytes) -> dict:
    try:
        import pytesseract
        from PIL import Image

        pil_img     = Image.open(io.BytesIO(image_bytes))
        extracted   = pytesseract.image_to_string(pil_img).strip()

        if not extracted:
            return {'error': 'No text could be extracted from this image. Ensure the image is clear and contains readable text.'}

        analysis = analyse_text(extracted)
        analysis['extracted_text'] = extracted
        analysis['char_count']     = len(extracted)
        analysis['word_count']     = len(extracted.split())
        analysis['scan_type']      = 'OCR Scanner'
        return analysis

    except ImportError as e:
        return {'error': f'pytesseract not installed or Tesseract binary missing: {e}'}
    except Exception as e:
        return {'error': f'OCR failed: {str(e)}'}

def analyse_pdf(pdf_bytes: bytes) -> dict:
    try:
        import pdfplumber

        text_pages  = []
        page_count  = 0

        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            page_count = len(pdf.pages)
            for page in pdf.pages:
                pt = page.extract_text()
                if pt:
                    text_pages.append(pt)
                if sum(len(t) for t in text_pages) >= 3000:
                    break

        full_text = '\n'.join(text_pages)[:3000]

        if not full_text.strip():
            return {'error': 'No readable text found in this PDF (it may be scanned or image-only).'}

        analysis = analyse_text(full_text)
        analysis['page_count']    = page_count
        analysis['word_count']    = len(full_text.split())
        analysis['char_count']    = len(full_text)
        analysis['preview_text']  = full_text[:500]
        analysis['scan_type']     = 'PDF Scanner'
        return analysis

    except ImportError:
        try:
            import PyPDF2
            reader     = PyPDF2.PdfReader(io.BytesIO(pdf_bytes))
            page_count = len(reader.pages)
            texts      = []
            for page in reader.pages:
                t = page.extract_text()
                if t:
                    texts.append(t)
            full_text = '\n'.join(texts)[:3000]
            if not full_text.strip():
                return {'error': 'No text extracted from PDF.'}
            analysis = analyse_text(full_text)
            analysis['page_count']   = page_count
            analysis['word_count']   = len(full_text.split())
            analysis['char_count']   = len(full_text)
            analysis['preview_text'] = full_text[:500]
            analysis['scan_type']    = 'PDF Scanner'
            return analysis
        except Exception as e2:
            return {'error': f'PDF extraction failed: {e2}'}
    except Exception as e:
        return {'error': f'PDF analysis failed: {str(e)}'}

def analyse_company(name: str, email: str, website: str) -> dict:
    """
    Full Company Verifier pipeline.

    Reuses the existing scanning pipelines rather than re-implementing them:
      - analyse_url_full()        → the same URL Scanner pipeline (heuristics +
                                      live page fetch + text ML + URL ML model)
                                      used on the URL Scanner page, run here
                                      against the company website.
      - analyse_email_full()      → recruiter-email pipeline (public/disposable
                                      provider checks, domain-vs-website match,
                                      scam keywords, entropy, digit ratio,
                                      typosquatting) from utils.py.
      - verify_company_identity() → cross-checks the claimed company name
                                      against the website domain, page title,
                                      and fetched page text.

    On top of those three pipelines, this function adds one more layer:
    cross-verification between all three inputs (name <-> email <-> website),
    then folds everything into a single 0-100 trust score with a level
    classification (Safe / Low / Medium / High / Critical) and a set of
    human-readable explanation bullets.
    """
    name    = (name or '').strip()
    email   = (email or '').strip()
    website = (website or '').strip()

    # 1. Run each existing pipeline
    url_result = analyse_url_full(website) if website else None
    website_domain = (url_result.get('domain', '') if url_result else '') or ''

    content = (url_result or {}).get('content_analysis', {}) or {}
    page_text = content.get('extracted_text', '') or content.get('content_snippet', '')

    identity_result = verify_company_identity(
        name, website_domain=website_domain,
        page_title=page_text, page_text=page_text,
    )
    email_result = analyse_email_full(
        email, website_domain=website_domain, company_name=name,
    ) if email else None

    # 2. Cross-verification between name / email / website
    cross_flags = []
    cross_penalty = 0

    email_domain = (email_result or {}).get('domain', '') if email_result else ''

    if name and email_result and email_domain:
        name_tokens = identity_result.get('tokens', [])
        significant = [t for t in name_tokens if len(t) >= 4] or name_tokens
        email_blob  = f"{email_result.get('local_part','')} {email_domain}".lower()
        name_in_email = any(t in email_blob for t in significant) if significant else False
        if significant and not name_in_email and not email_result.get('domain_matches_website'):
            cross_flags.append(
                f'Recruiter email ("{email}") appears unrelated to the company name ("{name}")'
            )
            cross_penalty += 20

    if email_result and email_result.get('domain_matches_website') is False and website_domain:
        cross_flags.append(
            f'Website ("{website_domain}") and recruiter email domain ("{email_domain}") do not match'
        )
        cross_penalty += 15

    if website_domain and identity_result.get('match_score', 0) == 0:
        cross_penalty += 20
    elif website_domain and not identity_result.get('name_matches_domain'):
        cross_penalty += 10

    fully_consistent = (
        bool(name and email_result and url_result)
        and identity_result.get('name_matches_domain')
        and bool(email_result.get('domain_matches_website'))
    )
    cross_bonus = 10 if fully_consistent else 0
    cross_score = max(0, min(100, cross_penalty - cross_bonus))

    # 3. Individual risk scores (0-100, higher = riskier)
    company_name_risk = min(len(identity_result.get('suspicious_terms', [])) * 20, 80)
    identity_mismatch_risk = (100 - identity_result.get('match_score', 0)) if website_domain else 0
    email_risk = email_result.get('email_risk_score', 0) if email_result else 0
    url_risk   = url_result.get('risk_score', 0) if url_result else 0

    # 4. Weighted combination into a single risk score
    weighted_parts = []
    if website:
        weighted_parts.append((url_risk, 0.35))
        weighted_parts.append((identity_mismatch_risk, 0.15))
    if email:
        weighted_parts.append((email_risk, 0.30))
    weighted_parts.append((company_name_risk, 0.10))
    weighted_parts.append((cross_score, 0.10))

    total_weight = sum(w for _, w in weighted_parts) or 1.0
    risk_score = round(sum(s * w for s, w in weighted_parts) / total_weight, 1)
    risk_score = max(0.0, min(100.0, risk_score))

    ri = compute_risk_level(risk_score)
    trust_score = max(0, round(100 - risk_score))

    # 5. Assemble flags / explanation bullets from every layer
    flags = []
    if identity_result.get('suspicious_terms'):
        flags.append(
            f"Company name contains common fraud-recruitment phrasing: {', '.join(identity_result['suspicious_terms'][:3])}"
        )
    if website_domain and not identity_result.get('name_matches_domain'):
        flags.append(
            f'Company name "{name}" does not clearly match the website domain ("{website_domain}")' if name else
            'No company name provided to compare against the website'
        )
    if email_result:
        flags.extend(email_result.get('flags', []))
    if url_result:
        flags.extend(url_result.get('flags', url_result.get('indicators', [])))
    flags.extend(cross_flags)
    flags = list(dict.fromkeys(flags))

    explanation_bullets = [f"- {f}" for f in flags[:8]] or ["- No significant red flags detected across name, email, or website."]

    level = ri['level']
    if level == 'CRITICAL':
        verdict = ("This company/recruiter profile shows multiple serious fraud indicators "
                   "across the name, email, and website:\n\n" + "\n".join(explanation_bullets))
    elif level == 'HIGH':
        verdict = ("Strong red flags detected - this profile is unlikely to be legitimate:\n\n"
                   + "\n".join(explanation_bullets))
    elif level == 'MEDIUM':
        verdict = ("Some suspicious or inconsistent elements were found. Verify independently "
                   "through official channels before proceeding:\n\n" + "\n".join(explanation_bullets))
    elif level == 'LOW':
        verdict = ("Only minor risk factors were identified. Still recommended to verify the "
                   "recruiter and offer through official channels:\n\n" + "\n".join(explanation_bullets))
    else:
        verdict = "Company name, recruiter email, and website appear consistent and largely legitimate."

    confidence = min(95, 45 + int(risk_score * 0.5) + (15 if (email and website) else 0))

    logger.info(
        "[Company Verifier] name=%r email=%r website=%r -> risk=%.1f level=%s "
        "(url=%.1f email=%.1f identity_mismatch=%.1f cross=%.1f)",
        name, email, website, risk_score, level, url_risk, email_risk,
        identity_mismatch_risk, cross_score,
    )

    return {
        'risk_score':         risk_score,
        'risk_level':         level,
        'risk_color':         ri['color'],
        'risk_emoji':         ri['emoji'],
        'confidence':         confidence,
        'trust_score':        trust_score,
        'company_analysis':   identity_result,
        'recruiter_analysis': email_result,
        'url_analysis':       url_result,
        'cross_verification': {
            'flags':      cross_flags,
            'penalty':    cross_penalty,
            'bonus':      cross_bonus,
            'consistent': fully_consistent,
        },
        'flags':            flags,
        'suspicious_kws':   flags[:8],
        'indicators':       flags,
        'recommendations':  get_recommendations(level),
        'verdict':          verdict,
        'scan_type':        'Company Verifier',
    }