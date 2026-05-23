# language_utils.py — CyberLens AI
# Multilingual support: auto-detect language + translate to English before analysis
#
# Supported languages:
#   Tamil (ta), English (en), Telugu (te), Malayalam (ml),
#   Kannada (kn), Hindi (hi), Spanish (es)
#
# Strategy (in priority order, zero-dependency first):
#   1. langdetect  — lightweight, offline, no API key needed
#   2. googletrans — free unofficial Google Translate API (no key)
#   3. deep-translator — fallback free translation library
#
# If ALL translation backends fail, the original text is returned unchanged
# so the rest of the CyberLens pipeline still works.

import re
import unicodedata
import streamlit as st

# ─── Language Metadata ──────────────────────────────────────────────────────────

SUPPORTED_LANGUAGES = {
    'ta': {'name': 'Tamil',     'native': 'தமிழ்',    'flag': '🇮🇳'},
    'en': {'name': 'English',   'native': 'English',   'flag': '🇬🇧'},
    'te': {'name': 'Telugu',    'native': 'తెలుగు',    'flag': '🇮🇳'},
    'ml': {'name': 'Malayalam', 'native': 'മലയാളം',   'flag': '🇮🇳'},
    'kn': {'name': 'Kannada',   'native': 'ಕನ್ನಡ',    'flag': '🇮🇳'},
    'hi': {'name': 'Hindi',     'native': 'हिन्दी',   'flag': '🇮🇳'},
    'es': {'name': 'Spanish',   'native': 'Español',   'flag': '🇪🇸'},
}

# Languages we can confidently handle
SUPPORTED_LANG_CODES = set(SUPPORTED_LANGUAGES.keys())

# Unicode block ranges for script-based heuristic detection
_SCRIPT_RANGES = {
    'hi': (0x0900, 0x097F),   # Devanagari → Hindi
    'ta': (0x0B80, 0x0BFF),   # Tamil
    'te': (0x0C00, 0x0C7F),   # Telugu
    'kn': (0x0C80, 0x0CFF),   # Kannada
    'ml': (0x0D00, 0x0D7F),   # Malayalam
}


# ─── Heuristic Script Detector (zero-dependency fallback) ─────────────────────

def _script_detect(text: str) -> str | None:
    """
    Count Unicode codepoints per Indic script block.
    Returns a language code if a script clearly dominates, else None.
    """
    counts = {lang: 0 for lang in _SCRIPT_RANGES}
    for ch in text:
        cp = ord(ch)
        for lang, (lo, hi) in _SCRIPT_RANGES.items():
            if lo <= cp <= hi:
                counts[lang] += 1

    total_script = sum(counts.values())
    if total_script == 0:
        return None  # no Indic script found

    best_lang = max(counts, key=counts.get)
    # Only return if the dominant script accounts for ≥60% of script chars
    if counts[best_lang] / total_script >= 0.60:
        return best_lang
    return None


def _is_mostly_latin(text: str) -> bool:
    latin = sum(1 for ch in text if 'LATIN' in unicodedata.name(ch, ''))
    return latin / max(len(text.replace(' ', '')), 1) > 0.75


# ─── Language Detection ────────────────────────────────────────────────────────

def detect_language(text: str) -> dict:
    """
    Detect the language of the input text.

    Returns:
        {
          'lang_code':   str,    e.g. 'ta', 'hi', 'en'
          'lang_name':   str,    e.g. 'Tamil'
          'native_name': str,    e.g. 'தமிழ்'
          'flag':        str,    e.g. '🇮🇳'
          'confidence':  float,  0.0–1.0
          'is_supported':bool,
          'method':      str,    'script' | 'langdetect' | 'fallback'
        }
    """
    text = text.strip()

    # 1️⃣  Script heuristic (fast, no deps, very reliable for Indic scripts)
    script_lang = _script_detect(text)
    if script_lang:
        meta = SUPPORTED_LANGUAGES.get(script_lang, {})
        return {
            'lang_code':   script_lang,
            'lang_name':   meta.get('name', script_lang),
            'native_name': meta.get('native', ''),
            'flag':        meta.get('flag', '🏳️'),
            'confidence':  0.97,
            'is_supported':True,
            'method':      'script',
        }

    # 2️⃣  langdetect library
    try:
        from langdetect import detect, detect_langs
        langs = detect_langs(text)
        if langs:
            top  = langs[0]
            code = top.lang
            conf = round(float(top.prob), 3)
            # Map some langdetect codes to ours (e.g. 'zh-cn' → unsupported)
            is_sup = code in SUPPORTED_LANG_CODES
            meta   = SUPPORTED_LANGUAGES.get(code, {})
            return {
                'lang_code':   code,
                'lang_name':   meta.get('name', code.upper()),
                'native_name': meta.get('native', ''),
                'flag':        meta.get('flag', '🏳️'),
                'confidence':  conf,
                'is_supported':is_sup,
                'method':      'langdetect',
            }
    except Exception:
        pass

    # 3️⃣  Latin script → English fallback
    if _is_mostly_latin(text):
        # Could be Spanish — simple heuristic: common Spanish markers
        es_markers = ['de ', 'la ', 'el ', 'en ', 'que ', 'con ', 'para ', 'por ', 'los ', 'las ']
        es_hits = sum(1 for m in es_markers if m in text.lower())
        if es_hits >= 3:
            meta = SUPPORTED_LANGUAGES['es']
            return {
                'lang_code': 'es', 'lang_name': meta['name'],
                'native_name': meta['native'], 'flag': meta['flag'],
                'confidence': 0.65, 'is_supported': True, 'method': 'fallback',
            }
        meta = SUPPORTED_LANGUAGES['en']
        return {
            'lang_code': 'en', 'lang_name': meta['name'],
            'native_name': meta['native'], 'flag': meta['flag'],
            'confidence': 0.70, 'is_supported': True, 'method': 'fallback',
        }

    # 4️⃣  Unknown
    return {
        'lang_code': 'unknown', 'lang_name': 'Unknown', 'native_name': '',
        'flag': '🏳️', 'confidence': 0.0, 'is_supported': False, 'method': 'fallback',
    }


# ─── Translation ───────────────────────────────────────────────────────────────

def translate_to_english(text: str, src_lang: str) -> dict:
    """
    Translate *text* from *src_lang* to English.

    Returns:
        {
          'translated_text': str,   # English text (or original if failed)
          'success':         bool,
          'method':          str,   # 'googletrans' | 'deep_translator' | 'passthrough'
          'error':           str | None,
        }
    """
    if src_lang == 'en':
        return {
            'translated_text': text,
            'success': True,
            'method': 'passthrough',
            'error': None,
        }

    # 1️⃣  googletrans (v4 async → use synchronous wrapper)
    try:
        from googletrans import Translator
        t = Translator()
        result = t.translate(text, src=src_lang, dest='en')
        translated = result.text
        if translated and translated.strip():
            return {
                'translated_text': translated,
                'success': True,
                'method': 'googletrans',
                'error': None,
            }
    except Exception as e1:
        _err1 = str(e1)
    else:
        _err1 = None

    # 2️⃣  deep-translator (GoogleTranslator)
    try:
        from deep_translator import GoogleTranslator
        translated = GoogleTranslator(source=src_lang, target='en').translate(text)
        if translated and translated.strip():
            return {
                'translated_text': translated,
                'success': True,
                'method': 'deep_translator',
                'error': None,
            }
    except Exception as e2:
        _err2 = str(e2)
    else:
        _err2 = None

    # 3️⃣  Passthrough — translation unavailable, return original
    return {
        'translated_text': text,
        'success': False,
        'method': 'passthrough',
        'error': 'Translation backends unavailable. Install googletrans or deep-translator.',
    }


# ─── Combined: Detect + Translate ─────────────────────────────────────────────

@st.cache_data(max_entries=256)
def detect_and_translate(text: str) -> dict:
    """
    Full pipeline: detect language → translate to English if needed.

    Returns:
        {
          'original_text':    str,
          'translated_text':  str,   # English (same as original if already English)
          'was_translated':   bool,
          'lang_code':        str,
          'lang_name':        str,
          'native_name':      str,
          'flag':             str,
          'confidence':       float,
          'is_supported':     bool,
          'translation_method': str,
          'translation_success': bool,
          'translation_error': str | None,
          'detect_method':    str,
        }
    """
    detection = detect_language(text)
    lang_code = detection['lang_code']

    if lang_code == 'en' or lang_code == 'unknown':
        return {
            'original_text':      text,
            'translated_text':    text,
            'was_translated':     False,
            'translation_method': 'passthrough',
            'translation_success':True,
            'translation_error':  None,
            'detect_method':      detection['method'],
            **{k: detection[k] for k in
               ('lang_code', 'lang_name', 'native_name', 'flag', 'confidence', 'is_supported')},
        }

    translation = translate_to_english(text, lang_code)

    return {
        'original_text':      text,
        'translated_text':    translation['translated_text'],
        'was_translated':     translation['success'],
        'translation_method': translation['method'],
        'translation_success':translation['success'],
        'translation_error':  translation['error'],
        'detect_method':      detection['method'],
        **{k: detection[k] for k in
           ('lang_code', 'lang_name', 'native_name', 'flag', 'confidence', 'is_supported')},
    }


# ─── Language Badge HTML ───────────────────────────────────────────────────────
# NOTE: Only uses div/span/strong — tags Streamlit's markdown renderer allows.
# <details>, <summary>, and most block-level tags are stripped by Streamlit.
# The original-text preview is handled via st.expander() in app.py, not here.

def language_badge_html(lang_result: dict) -> str:
    """
    Returns a safe HTML string (div/span only) for the language detection badge.
    Render with:  st.markdown(badge_html, unsafe_allow_html=True)
    """
    flag      = lang_result.get('flag', '🏳️')
    lang_name = lang_result.get('lang_name', 'Unknown')
    native    = lang_result.get('native_name', '')
    conf      = round(lang_result.get('confidence', 0) * 100)
    was_trans = lang_result.get('was_translated', False)
    method    = lang_result.get('translation_method', '')
    t_success = lang_result.get('translation_success', False)

    native_str = f' · {native}' if native and native != lang_name else ''
    t_color    = '#00ff9d' if t_success else '#ffb340'
    t_label    = f'✅ Translated via {method}' if (was_trans and t_success) else (
                 f'⚠️ Translation unavailable — original text analysed' if was_trans else '')

    trans_row = f'''
        <div style="margin-top:0.35rem;font-size:0.72rem;color:{t_color};
                    font-family:monospace;letter-spacing:0.03em">
            🌐 {t_label}
        </div>''' if was_trans else ''

    return f'''
    <div style="
        display:inline-flex;flex-direction:column;
        background:rgba(0,212,255,0.07);
        border:1px solid rgba(0,212,255,0.22);
        border-radius:12px;padding:0.5rem 1rem;
        margin-bottom:0.75rem;">
        <div style="display:flex;align-items:center;gap:0.5rem;
                    font-family:monospace;font-size:0.75rem;color:#00d4ff;">
            <span style="font-size:1.05rem">{flag}</span>
            <span>Language detected: <strong>{lang_name}</strong>{native_str}</span>
            <span style="color:rgba(0,212,255,0.4)">·</span>
            <span style="color:rgba(0,212,255,0.75)">{conf}% confidence</span>
        </div>{trans_row}
    </div>'''
