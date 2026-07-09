# analyzer.py — CyberLens AI
# High-level analysis wrappers used by app.py

import io
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

_WIN_TESS = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
if os.name == 'nt':
    pytesseract.pytesseract.tesseract_cmd = _WIN_TESS

from utils import (
    score_keywords, compute_risk_level, normalise_score,
    analyse_url, analyse_recruiter_email, analyse_company_name,
    SCAM_KEYWORDS,
)
from ml_model import predict as ml_predict, get_feature_importance
from url_model import predict_url as url_ml_predict
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

    verdict = (
        'This content shows strong indicators of a scam or phishing attempt.'
        if level in ('CRITICAL', 'HIGH') else
        'This content contains some suspicious elements worth investigating.'
        if level == 'MEDIUM' else
        'This content appears largely legitimate but warrants basic verification.'
        if level == 'LOW' else
        'This content appears safe with no significant threat indicators detected.'
    )

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
    """
    Sub-render using Playwright framework when static requests cannot retrieve content
    """
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
        'error':              None,
        'text_model_label':       None,
        'text_model_probability': 0.0,
        'extracted_text_len':     0,
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
            'final_hybrid_score': 0.0,
        }
    }

    fetch_url = url.strip()
    if not fetch_url.startswith(('http://', 'https://')):
        fetch_url = 'http://' + fetch_url
    result['url_used'] = fetch_url

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

        is_cloudflare = False
        server_header = resp.headers.get('Server', '').lower()
        if 'cloudflare' in server_header or 'cloudflare' in resp.text.lower() or 'ray id' in resp.text.lower():
            is_cloudflare = True

        if status_code == 403:
            if is_cloudflare:
                result['error'] = "Access blocked by Cloudflare bot protection (HTTP 403)."
            else:
                result['error'] = "Access denied by website server (HTTP 403 Forbidden)."
        elif status_code == 404:
            result['error'] = "The website was not found (HTTP 404 Not Found)."
        elif status_code >= 500:
            result['error'] = f"The website server returned an error (HTTP {status_code})."
        else:
            resp.raise_for_status()
            html_content = resp.text

    except requests.exceptions.Timeout:
        result['error'] = "The website took too long to respond (timeout)."
    except requests.exceptions.SSLError:
        result['error'] = "Could not verify the site's SSL certificate."
    except requests.exceptions.ConnectionError:
        result['error'] = "Could not connect to the website — it may be down, blocking requests, or connection refused."
    except requests.exceptions.HTTPError:
        status = resp.status_code if 'resp' in locals() else '?'
        result['error'] = f"The website returned an error (HTTP {status})."
    except Exception as e:
        result['error'] = f"Unable to fetch this website: {str(e)}"

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
            try:
                pw_html, pw_status, pw_err = fetch_via_playwright(fetch_url, timeout_ms=8000)
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
            except ImportError:
                if js_required:
                    result['error'] = "This webpage requires JavaScript rendering. Static HTML contained insufficient content for analysis."
            except Exception as e:
                if js_required:
                    result['error'] = f"This webpage requires JavaScript rendering, but browser automation failed: {str(e)}"

    if visible_text and len(visible_text.strip()) >= 15:
        visible_lower = visible_text.lower()
        found = [p for p in SCAM_CONTENT_PHRASES if p in visible_lower]

        result['fetched']            = True
        result['suspicious_phrases'] = found
        result['content_snippet']    = visible_text[:500]
        result['extracted_text_len'] = len(visible_text)

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
        except Exception:
            pass

        result['debug_logs']['reached_text_model'] = reached_text_model
        result['debug_logs']['text_ml_prob'] = text_ml_prob
        
        # Calculate text rules core
        from ml_model import rule_based_scam_score
        result['debug_logs']['rule_score'] = rule_based_scam_score(visible_text)

    result['debug_logs']['extracted_text_len'] = len(visible_text)
    result['debug_logs']['extraction_method'] = extraction_method if visible_text else "Failed"
    result['debug_logs']['js_rendering_used'] = js_rendering_used

    return result

def analyse_url_full(url: str) -> dict:
    """Wrap utils.analyse_url with a friendly result envelope."""
    if not url or not url.strip():
        return {'error': 'No URL provided'}

    base = analyse_url(url)
    rs   = base['risk_score']
    ri   = base['risk_level']

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

    final_score = max(min(rs + content_bonus + ml_bonus + text_ml_bonus, 100), false_safe_floor)
    final_ri    = compute_risk_level(final_score)

    indicators = list(dict.fromkeys(indicators))

    # Explanation bullets
    explanation_bullets = []
    text_lower_all = (content_result.get('content_snippet', '') + " " + url).lower()
    
    if any(term in text_lower_all for term in ['registration fee', 'joining fee', 'processing fee', 'deposit', 'pay fee']):
        explanation_bullets.append("✓ Registration/processing fee detected")
    if any(term in text_lower_all for term in ['urgent', 'immediately', 'immediate', 'act now', 'limited offer', 'expiring', 'today only']):
        explanation_bullets.append("✓ Urgent/time-pressure language detected")
    if base['tld_risk'] > 0 or base['has_ip'] or base['typosquat_risk'] or '@' in url:
        explanation_bullets.append("✓ Suspicious domain or TLD structure")
    if len(scam_phrases) > 0 or len(base['suspicious_kw']) > 0:
        explanation_bullets.append("✓ Scam/phishing keywords identified")
    if (url_ml_result.get('label') == 'phishing' and ml_prob >= 0.5) or (text_ml_prob >= 0.5):
        explanation_bullets.append("✓ Flagged with high confidence by AI threat models")

    if explanation_bullets:
        verdict = "This URL has been flagged with multiple high-risk indicators:\n\n" + "\n".join(explanation_bullets)
    else:
        if final_score >= 65:
            verdict = "This URL shows strong phishing indicators and is likely malicious."
        elif final_score >= 30:
            verdict = "This URL has some suspicious characteristics. Exercise caution."
        else:
            verdict = "This URL appears relatively safe, but always verify the source."

    debug_logs = content_result.get('debug_logs', {})
    debug_logs['final_hybrid_score'] = final_score
    debug_logs['url_ml_prob'] = ml_prob
    debug_logs['url_heuristic_score'] = rs

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
        'text_model_label':       content_result.get('text_model_label'),
        'text_model_probability': round(text_ml_prob * 100, 1),
        'debug_logs':      debug_logs,
    }

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

        qr_type = 'QRCODE'
        is_url  = qr_data.startswith(('http://', 'https://')) or '.' in qr_data.split('/')[0]
        result  = {'qr_data': qr_data, 'qr_type': qr_type, 'is_url': is_url}

        if is_url:
            url_result = analyse_url_full(qr_data)
            result.update(url_result)
        else:
            text_result = analyse_text(qr_data)
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
    parts = []

    company_result   = analyse_company_name(name)
    recruiter_result = analyse_recruiter_email(email) if email else None
    url_result       = analyse_url_full(website) if website else None

    scores = [company_result['risk_score']]
    if recruiter_result:
        scores.append(70 if recruiter_result['is_free_mail'] else 10)
    if url_result:
        scores.append(url_result.get('risk_score', 0))

    combined = round(sum(scores) / len(scores), 1)
    ri       = compute_risk_level(combined)

    flags = company_result['suspicious_terms'][:]
    if recruiter_result and recruiter_result['is_free_mail']:
        flags.append(f"Free-mail domain used: {recruiter_result['domain']}")
    if url_result and url_result.get('flags'):
        flags.extend(url_result['flags'])

    return {
        'risk_score':        combined,
        'risk_level':        ri['level'],
        'risk_color':        ri['color'],
        'risk_emoji':        ri['emoji'],
        'confidence':        min(90, 40 + int(combined)),
        'company_analysis':  company_result,
        'recruiter_analysis': recruiter_result,
        'url_analysis':      url_result,
        'flags':             flags,
        'suspicious_kws':    flags[:8],
        'recommendations':   get_recommendations(ri['level']),
        'verdict': (
            'This company/recruiter profile shows serious red flags of fraud.'
            if combined >= 65 else
            'Some suspicious elements detected. Verify through official channels.'
            if combined >= 35 else
            'Profile appears largely legitimate.'
        ),
        'scan_type': 'Company Verifier',
        'trust_score': max(0, 100 - int(combined)),
    }