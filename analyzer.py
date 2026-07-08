# analyzer.py — CyberLens AI
# High-level analysis wrappers used by app.py

import io
import os
import re
import time
import numpy as np
import pytesseract
import requests                       # NEW: used for safe webpage content fetching (URL Scanner enhancement)
from bs4 import BeautifulSoup         # NEW: used to extract only visible text from fetched pages

# ── Cross-platform Tesseract path ───────────────────────────────────────────────
_WIN_TESS = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
if os.name == 'nt':
    pytesseract.pytesseract.tesseract_cmd = _WIN_TESS
# On Linux/Mac, tesseract is expected to be on PATH (installed via apt/brew)

from utils import (
    score_keywords, compute_risk_level, normalise_score,
    analyse_url, analyse_recruiter_email, analyse_company_name,
    SCAM_KEYWORDS,
)
from ml_model import predict as ml_predict, get_feature_importance
from url_model import predict_url as url_ml_predict
from language_utils import detect_and_translate

# ─── Shared Recommendation Bank ─────────────────────────────────────────────────

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


# ─── Text / Message Analysis ─────────────────────────────────────────────────────

def analyse_text(text: str) -> dict:
    """
    Full pipeline: language detection → translation → ML prediction +
    keyword heuristics → combined risk score.
    """
    if not text or not text.strip():
        return {'error': 'No text provided'}

    # ── Multilingual: detect language and translate to English ──────────────────
    lang_result   = detect_and_translate(text)
    analysis_text = lang_result['translated_text']   # English (or original if en/unknown)

    # ML prediction (always on English text)
    ml_result    = ml_predict(analysis_text)
    ml_scam_prob = ml_result['probability']   # 0–1

    # Keyword heuristics — run on BOTH original and translated text, take the higher score.
    # This ensures India-specific terms (aadhaar, pan card, kyc) are not lost in translation.
    kw_translated = score_keywords(analysis_text)
    kw_original   = score_keywords(lang_result['original_text'])
    kw_result     = kw_translated if kw_translated['score'] >= kw_original['score'] else kw_original
    kw_raw        = kw_result['score']
    kw_norm       = normalise_score(kw_raw, ceiling=20.0)   # ceiling matches utils.py default

    # Blend: 45% ML + 55% keyword heuristic.
    # Keywords are hand-crafted scam signals and more reliable than a small-data ML model.
# Confidence-aware blend: trust whichever signal is stronger.
    if kw_norm >= 60:
        ml_weight, kw_weight = 0.30, 0.70   # strong keyword signal → trust it
    elif kw_norm <= 10:
        ml_weight, kw_weight = 0.70, 0.30   # no keyword signal → lean on ML
    else:
        ml_weight, kw_weight = 0.45, 0.55   # ambiguous → current default

    blended = (ml_scam_prob * 100 * ml_weight) + (kw_norm * kw_weight)
    blended = min(round(blended, 1), 100.0)
    
    risk_info   = compute_risk_level(blended)
    level       = risk_info['level']
    confidence  = round(ml_result['confidence'] * 100, 1)

    # Top TF-IDF features for explainability
    top_features = get_feature_importance(text, top_n=8)
    feature_words = [f[0] for f in top_features]

    # Merge with keyword hits for display
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
        # ── Language info ──────────────────────────────────────────────────────
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


# ─── NEW: Webpage Content Analysis (URL Scanner enhancement) ─────────────────────
# Fetches the page's HTML *server-side* (the user's browser never visits the
# site) and scans only the visible text for common scam / phishing phrases.
# This never opens the website for the user — it only reads its content safely.

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
]

def analyse_webpage_content(url: str, timeout: int = 6) -> dict:
    """
    Safely fetch a webpage's HTML (server-side only — never opens it in the
    user's browser) and scan its *visible* text for scam/phishing phrases.
    Always returns a dict and never raises, so a bad/unreachable URL cannot
    crash the scanner.
    """
    result = {
        'fetched':            False,
        'url_used':           url,
        'suspicious_phrases': [],
        'content_snippet':    '',
        'error':              None,
    }

    fetch_url = url.strip()
    if not fetch_url.startswith(('http://', 'https://')):
        fetch_url = 'http://' + fetch_url
    result['url_used'] = fetch_url

    try:
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; CyberLensAI-Scanner/1.0)'}
        resp = requests.get(fetch_url, headers=headers, timeout=timeout, allow_redirects=True)
        resp.raise_for_status()

        soup = BeautifulSoup(resp.text, 'html.parser')
        for tag in soup(['script', 'style', 'noscript', 'head']):
            tag.decompose()
        visible_text = soup.get_text(separator=' ', strip=True)
        visible_lower = visible_text.lower()

        found = [p for p in SCAM_CONTENT_PHRASES if p in visible_lower]

        result['fetched']            = True
        result['suspicious_phrases'] = found
        result['content_snippet']    = visible_text[:500]

    except requests.exceptions.Timeout:
        result['error'] = 'The website took too long to respond (timeout).'
    except requests.exceptions.SSLError:
        result['error'] = "Could not verify the site's SSL certificate."
    except requests.exceptions.ConnectionError:
        result['error'] = 'Could not connect to the website — it may be down or blocking requests.'
    except requests.exceptions.HTTPError:
        status = resp.status_code if 'resp' in locals() else '?'
        result['error'] = f'The website returned an error (HTTP {status}).'
    except Exception:
        result['error'] = "Unable to fetch or analyse this website's content."

    return result


# ─── URL Analysis ─────────────────────────────────────────────────────────────────

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

    # ── NEW: Webpage content analysis (does not alter the URL heuristic above) ──
    content_result = analyse_webpage_content(url)
    scam_phrases    = content_result.get('suspicious_phrases', [])
    if scam_phrases:
        indicators.append(f"Scam phrases found on page: {', '.join(scam_phrases[:4])}")

    # Content-based signal is additive on top of the existing URL score, so the
    # original URL detection logic/weights above remain completely unchanged.
    content_bonus = min(15 * len(scam_phrases), 45)

    # ── NEW: Phishing URL ML model (trained on url.csv) ─────────────────────────
    # Runs as a separate pipeline from the text scam model. If no model/data is
    # available it returns label='unknown' and contributes nothing, so behaviour
    # for existing deployments without url.csv is completely unchanged.
    url_ml_result = url_ml_predict(url)
    ml_prob       = url_ml_result.get('probability', 0.0)
    if url_ml_result.get('label') != 'unknown':
        indicators.append(f"AI model flags URL as {url_ml_result['label']} "
                           f"({round(ml_prob * 100)}% confidence)" if url_ml_result['label'] == 'phishing' else
                           "AI model rates URL as likely legitimate")
        ml_bonus = round(ml_prob * 40)   # ML contributes up to +40 on top of heuristic score
    else:
        ml_bonus = 0

    final_score = min(rs + content_bonus + ml_bonus, 100)
    final_ri    = compute_risk_level(final_score) if (content_bonus or ml_bonus) else ri

    verdict = (
        f"This URL shows {len(indicators)} phishing indicator(s) and is likely malicious."
        if final_score >= 65 else
        f"This URL has some suspicious characteristics ({len(indicators)} flag(s))."
        if final_score >= 30 else
        'This URL appears relatively safe, but always verify the source.'
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
        'confidence':      min(90, 50 + final_score // 2),
        'scan_type':       'URL Scanner',
        'content_analysis':content_result,   # NEW: used by the URL Scanner page UI
        'open_url':        content_result.get('url_used', url),
        'url_ml_label':      url_ml_result.get('label', 'unknown'),      # NEW
        'url_ml_probability':round(ml_prob * 100, 1),                    # NEW
    }


# ─── QR Code Analysis ─────────────────────────────────────────────────────────────

def analyse_qr(image_bytes: bytes) -> dict:
    """Decode a QR code from image bytes and analyse the extracted URL/text."""
    try:
        import cv2
        from PIL import Image
        import numpy as np

        pil_img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
        cv_img  = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)

        # ── Try OpenCV QRCodeDetector first ─────────────────────────────────────
        qr_detector = cv2.QRCodeDetector()
        qr_data, bbox, _ = qr_detector.detectAndDecode(cv_img)

        # ── Fallback: try WeChatQRCode if available (more robust) ───────────────
        if not qr_data:
            try:
                wechat_detector = cv2.wechat_qrcode_WeChatQRCode()
                texts, _ = wechat_detector.detectAndDecode(cv_img)
                if texts:
                    qr_data = texts[0]
            except Exception:
                pass

        # ── Final fallback: try grayscale + threshold to improve detection ───────
        if not qr_data:
            gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
            _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            gray_3ch = cv2.cvtColor(thresh, cv2.COLOR_GRAY2BGR)
            qr_data, bbox, _ = qr_detector.detectAndDecode(gray_3ch)

        if not qr_data:
            return {'error': 'No QR code detected in the image. Please ensure the QR code is clear, well-lit, and not blurry.'}

        qr_type = 'QRCODE'   # OpenCV only decodes QR codes (not barcodes)

        # Determine if it's a URL
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


# ─── OCR Analysis ─────────────────────────────────────────────────────────────────

def analyse_ocr_image(image_bytes: bytes) -> dict:
    """Extract text via OCR, then run scam analysis on the extracted content."""
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


# ─── PDF Analysis ─────────────────────────────────────────────────────────────────

def analyse_pdf(pdf_bytes: bytes) -> dict:
    """Extract text from PDF (first 3000 chars) and run scam analysis."""
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
        # Fallback to PyPDF2
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


# ─── Company / Recruiter Verification ─────────────────────────────────────────────

def analyse_company(name: str, email: str, website: str) -> dict:
    """Holistic company/recruiter legitimacy check."""
    parts = []

    company_result   = analyse_company_name(name)
    recruiter_result = analyse_recruiter_email(email) if email else None
    url_result       = analyse_url_full(website) if website else None

    # Aggregate risk
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
        'recruiter_analysis':recruiter_result,
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
