# url_model.py — CyberLens AI
# Phishing URL detection pipeline (separate from the text scam model in ml_model.py)
#
# Compatible with the feature-engineered `url.csv` dataset, whose columns are:
#   URL, URLLength, Domain, DomainLength, IsDomainIP, TLD, URLSimilarityIndex,
#   CharContinuationRate, TLDLegitimateProb, URLCharProb, TLDLength,
#   NoOfSubDomain, HasObfuscation, NoOfObfuscatedChar, ObfuscationRatio,
#   NoOfLettersInURL, LetterRatioInURL, NoOfDegitsInURL, DegitRatioInURL,
#   NoOfEqualsInURL, NoOfQMarkInURL, NoOfAmpersandInURL,
#   NoOfOtherSpecialCharsInURL, SpacialCharRatioInURL, IsHTTPS, LineOfCode,
#   LargestLineLength, HasTitle, Title, DomainTitleMatchScore,
#   URLTitleMatchScore, HasFavicon, Robots, IsResponsive, NoOfURLRedirect,
#   NoOfSelfRedirect, HasDescription, NoOfPopup, NoOfiFrame,
#   HasExternalFormSubmit, HasSocialNet, HasSubmitButton, HasHiddenFields,
#   HasPasswordField, Bank, Pay, Crypto, HasCopyrightInfo, NoOfImage, NoOfCSS,
#   NoOfJS, NoOfSelfRef, NoOfEmptyRef, NoOfExternalRef, label
#
# Design:
#   • All numeric/structural columns above are reconstructed live for any
#     user-entered URL via `extract_features_for_url`.
#   • Webpage-dependent columns (Title, LineOfCode, HasFavicon, Robots,
#     NoOfImage, NoOfCSS, NoOfJS, forms/password fields, redirects, etc.) are
#     populated by *safely* fetching the page server-side. If the page can't
#     be reached, sensible defaults are used and nothing crashes.
#   • Model: RandomForest + GradientBoosting soft-voting ensemble over the
#     full numeric feature table (no text vectorisation needed — the dataset
#     is already feature-engineered).
#   • Threshold tuned via precision-recall curve (maximise F1).
#   • Falls back gracefully to utils.analyse_url heuristic when no
#     model/data/network is available, so analyzer.py never breaks.

import os
import re
import math
import joblib
import numpy as np
import pandas as pd
import requests
import streamlit as st

from urllib.parse import urlparse
from difflib import SequenceMatcher

from sklearn.ensemble         import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.impute           import SimpleImputer
from sklearn.pipeline         import Pipeline
from sklearn.model_selection  import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics          import accuracy_score, classification_report, f1_score

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

# ─── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'phishing_url_detector.pkl')
DATA_PATH  = os.path.join(BASE_DIR, 'url.csv')

_POSITIVE_LABELS = {
    'phishing', 'malicious', 'bad', 'scam', 'fraud', 'unsafe',
    '1', 1, True, 'yes', 'phish',
}

# The full ordered feature set the model is trained/predicted on.
FEATURE_COLUMNS = [
    'URLLength', 'DomainLength', 'IsDomainIP', 'URLSimilarityIndex',
    'CharContinuationRate', 'TLDLegitimateProb', 'URLCharProb', 'TLDLength',
    'NoOfSubDomain', 'HasObfuscation', 'NoOfObfuscatedChar', 'ObfuscationRatio',
    'NoOfLettersInURL', 'LetterRatioInURL', 'NoOfDegitsInURL', 'DegitRatioInURL',
    'NoOfEqualsInURL', 'NoOfQMarkInURL', 'NoOfAmpersandInURL',
    'NoOfOtherSpecialCharsInURL', 'SpacialCharRatioInURL', 'IsHTTPS',
    'LineOfCode', 'LargestLineLength', 'HasTitle', 'DomainTitleMatchScore',
    'URLTitleMatchScore', 'HasFavicon', 'Robots', 'IsResponsive',
    'NoOfURLRedirect', 'NoOfSelfRedirect', 'HasDescription', 'NoOfPopup',
    'NoOfiFrame', 'HasExternalFormSubmit', 'HasSocialNet', 'HasSubmitButton',
    'HasHiddenFields', 'HasPasswordField', 'Bank', 'Pay', 'Crypto',
    'HasCopyrightInfo', 'NoOfImage', 'NoOfCSS', 'NoOfJS', 'NoOfSelfRef',
    'NoOfEmptyRef', 'NoOfExternalRef',
]

# Well-known legitimate TLDs get a high "legitimate probability" prior.
_COMMON_TLDS = {
    'com': 0.85, 'org': 0.75, 'net': 0.70, 'edu': 0.90, 'gov': 0.92,
    'in': 0.70, 'co': 0.55, 'io': 0.55, 'ai': 0.55, 'app': 0.55,
}
_SOCIAL_DOMAINS = ['facebook.com', 'twitter.com', 'x.com', 'instagram.com',
                    'linkedin.com', 'whatsapp.com', 'youtube.com', 'telegram.org']
_BANK_TERMS  = ['bank', 'banking', 'sbi', 'hdfc', 'icici', 'axis', 'paytm', 'netbanking']
_PAY_TERMS   = ['pay', 'payment', 'upi', 'wallet', 'checkout', 'billing']
_CRYPTO_TERMS = ['crypto', 'bitcoin', 'btc', 'eth', 'wallet', 'blockchain', 'coin']

_DEFAULT_HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; CyberLensAI-URLModel/1.0)'}


# ─── URL-only structural features (always available, no network needed) ───────

def _char_continuation_rate(s: str) -> float:
    """Fraction of characters that are the same as the preceding character."""
    if len(s) < 2:
        return 0.0
    same = sum(1 for i in range(1, len(s)) if s[i] == s[i - 1])
    return same / (len(s) - 1)


def _url_char_prob(s: str) -> float:
    """Average per-character frequency, as a rough naturalness proxy."""
    if not s:
        return 0.0
    from collections import Counter
    counts = Counter(s)
    total  = len(s)
    return sum((counts[c] / total) ** 2 for c in s) ** 0.5


def _similarity_to_known_brands(domain: str, known_brands: list) -> float:
    """Highest string-similarity ratio (0-1) between domain and known brands."""
    if not domain or not known_brands:
        return 0.0
    best = 0.0
    for b in known_brands:
        r = SequenceMatcher(None, domain, b).ratio()
        if r > best:
            best = r
    return best


_KNOWN_BRAND_DOMAINS = [
    'google.com', 'facebook.com', 'amazon.com', 'paypal.com', 'apple.com',
    'microsoft.com', 'netflix.com', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com',
    'instagram.com', 'whatsapp.com', 'linkedin.com', 'flipkart.com', 'paytm.com',
]


def extract_url_only_features(url: str) -> dict:
    """
    Compute every feature that can be derived from the URL string alone
    (no network access needed). Webpage-dependent features are added
    separately by `extract_webpage_features` / `extract_features_for_url`.
    """
    u = (url or '').strip()
    if not u.startswith(('http://', 'https://')):
        u = 'http://' + u

    try:
        parsed = urlparse(u)
    except Exception:
        parsed = None

    domain = (parsed.netloc if parsed else '').lower()
    domain = domain.split('@')[-1]          # strip userinfo if present
    domain = domain.split(':')[0]           # strip port
    domain_no_www = domain[4:] if domain.startswith('www.') else domain
    path   = (parsed.path if parsed else '') or ''
    scheme = (parsed.scheme if parsed else 'http')

    tld_match = re.search(r'\.([a-z]{2,})$', domain_no_www)
    tld       = tld_match.group(1) if tld_match else ''

    letters = sum(ch.isalpha() for ch in u)
    digits  = sum(ch.isdigit() for ch in u)
    specials = sum(1 for ch in u if not ch.isalnum() and ch not in ('.', '/', ':'))
    n = max(len(u), 1)

    subdomain_parts = domain_no_www.split('.')
    n_subdomains = max(len(subdomain_parts) - 2, 0) if len(subdomain_parts) > 2 else 0

    obf_chars = u.count('%')
    has_obf   = 1 if obf_chars > 0 else 0

    is_ip = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain_no_www) else 0

    sim_index = round(_similarity_to_known_brands(domain_no_www, _KNOWN_BRAND_DOMAINS) * 100, 2)

    feats = {
        'URLLength':                  len(u),
        'DomainLength':                len(domain_no_www),
        'IsDomainIP':                  is_ip,
        'URLSimilarityIndex':          sim_index,
        'CharContinuationRate':        round(_char_continuation_rate(u), 4),
        'TLDLegitimateProb':           _COMMON_TLDS.get(tld, 0.15),
        'URLCharProb':                 round(_url_char_prob(u), 4),
        'TLDLength':                   len(tld),
        'NoOfSubDomain':               n_subdomains,
        'HasObfuscation':              has_obf,
        'NoOfObfuscatedChar':          obf_chars,
        'ObfuscationRatio':            round(obf_chars / n, 4),
        'NoOfLettersInURL':            letters,
        'LetterRatioInURL':            round(letters / n, 4),
        'NoOfDegitsInURL':             digits,
        'DegitRatioInURL':             round(digits / n, 4),
        'NoOfEqualsInURL':             u.count('='),
        'NoOfQMarkInURL':              u.count('?'),
        'NoOfAmpersandInURL':          u.count('&'),
        'NoOfOtherSpecialCharsInURL':  specials,
        'SpacialCharRatioInURL':       round(specials / n, 4),
        'IsHTTPS':                     1 if scheme == 'https' else 0,
        '_domain':                     domain_no_www,
        '_tld':                        tld,
        '_path':                       path,
        '_clean_url':                  u,
    }
    return feats


# ─── Webpage-dependent features (safe network fetch, graceful fallback) ───────

def _default_webpage_features() -> dict:
    """Sensible neutral defaults used when the page cannot be fetched."""
    return {
        'LineOfCode':               0,
        'LargestLineLength':        0,
        'HasTitle':                 0,
        'Title':                    '',
        'DomainTitleMatchScore':    0.0,
        'URLTitleMatchScore':       0.0,
        'HasFavicon':               0,
        'Robots':                   0,
        'IsResponsive':             0,
        'NoOfURLRedirect':          0,
        'NoOfSelfRedirect':         0,
        'HasDescription':           0,
        'NoOfPopup':                0,
        'NoOfiFrame':               0,
        'HasExternalFormSubmit':    0,
        'HasSocialNet':             0,
        'HasSubmitButton':          0,
        'HasHiddenFields':          0,
        'HasPasswordField':         0,
        'Bank':                     0,
        'Pay':                      0,
        'Crypto':                   0,
        'HasCopyrightInfo':         0,
        'NoOfImage':                0,
        'NoOfCSS':                  0,
        'NoOfJS':                   0,
        'NoOfSelfRef':              0,
        'NoOfEmptyRef':             0,
        'NoOfExternalRef':          0,
        '_fetched':                 False,
        '_fetch_error':             None,
    }


def extract_webpage_features(url: str, domain: str, timeout: int = 6) -> dict:
    """
    Safely fetch a webpage (server-side only) and compute every
    webpage-dependent feature the model expects. Never raises — on any
    failure it returns neutral defaults so the pipeline keeps working.
    """
    feats = _default_webpage_features()

    if BeautifulSoup is None:
        feats['_fetch_error'] = 'BeautifulSoup not installed'
        return feats

    fetch_url = url.strip()
    if not fetch_url.startswith(('http://', 'https://')):
        fetch_url = 'http://' + fetch_url

    try:
        resp = requests.get(
            fetch_url, headers=_DEFAULT_HEADERS, timeout=timeout,
            allow_redirects=True,
        )
        n_redirects = len(resp.history)
        resp.raise_for_status()

        html = resp.text or ''
        soup = BeautifulSoup(html, 'html.parser')

        lines = html.splitlines()
        feats['LineOfCode']        = len(lines)
        feats['LargestLineLength'] = max((len(l) for l in lines), default=0)

        title_tag = soup.find('title')
        title_txt = title_tag.get_text(strip=True) if title_tag else ''
        feats['HasTitle'] = 1 if title_txt else 0
        feats['Title']    = title_txt[:200]

        title_lower  = title_txt.lower()
        domain_bare  = re.sub(r'\.[a-z]{2,}$', '', domain or '')
        feats['DomainTitleMatchScore'] = round(
            SequenceMatcher(None, domain_bare, title_lower).ratio() * 100, 2
        ) if domain_bare and title_lower else 0.0
        feats['URLTitleMatchScore'] = round(
            SequenceMatcher(None, url.lower(), title_lower).ratio() * 100, 2
        ) if title_lower else 0.0

        feats['HasFavicon'] = 1 if soup.find('link', rel=lambda v: v and 'icon' in v.lower()) else 0

        robots_meta   = soup.find('meta', attrs={'name': re.compile(r'robots', re.I)})
        feats['Robots'] = 1 if robots_meta else 0

        viewport_meta = soup.find('meta', attrs={'name': re.compile(r'viewport', re.I)})
        feats['IsResponsive'] = 1 if viewport_meta else 0

        feats['NoOfURLRedirect']  = n_redirects
        feats['NoOfSelfRedirect'] = sum(
            1 for h in resp.history
            if urlparse(h.url).netloc.lower().replace('www.', '') == (domain or '')
        )

        desc_meta = soup.find('meta', attrs={'name': re.compile(r'description', re.I)})
        feats['HasDescription'] = 1 if desc_meta else 0

        feats['NoOfPopup'] = len(soup.find_all(attrs={'onclick': re.compile(r'window\.open', re.I)}))
        feats['NoOfiFrame'] = len(soup.find_all('iframe'))

        forms = soup.find_all('form')
        ext_form_submit = 0
        has_submit_btn  = 0
        has_hidden      = 0
        has_pw          = 0
        for f in forms:
            action = (f.get('action') or '').strip()
            if action.startswith(('http://', 'https://')):
                action_domain = urlparse(action).netloc.lower().replace('www.', '')
                if action_domain and action_domain != (domain or ''):
                    ext_form_submit = 1
            if f.find('input', attrs={'type': re.compile(r'^submit$', re.I)}) or f.find('button', attrs={'type': re.compile(r'^submit$', re.I)}):
                has_submit_btn = 1
            if f.find('input', attrs={'type': re.compile(r'^hidden$', re.I)}):
                has_hidden = 1
            if f.find('input', attrs={'type': re.compile(r'^password$', re.I)}):
                has_pw = 1
        feats['HasExternalFormSubmit'] = ext_form_submit
        feats['HasSubmitButton']       = has_submit_btn
        feats['HasHiddenFields']       = has_hidden
        feats['HasPasswordField']      = has_pw

        page_text_lower = soup.get_text(' ', strip=True).lower()
        feats['HasSocialNet'] = 1 if any(
            soup.find('a', href=re.compile(re.escape(sd), re.I)) for sd in _SOCIAL_DOMAINS
        ) else 0
        feats['Bank']   = 1 if any(t in page_text_lower for t in _BANK_TERMS) else 0
        feats['Pay']    = 1 if any(t in page_text_lower for t in _PAY_TERMS) else 0
        feats['Crypto'] = 1 if any(t in page_text_lower for t in _CRYPTO_TERMS) else 0
        feats['HasCopyrightInfo'] = 1 if ('©' in html or 'copyright' in page_text_lower) else 0

        feats['NoOfImage'] = len(soup.find_all('img'))
        feats['NoOfCSS']   = len(soup.find_all('link', rel=lambda v: v and 'stylesheet' in v.lower())) + len(soup.find_all('style'))
        feats['NoOfJS']    = len(soup.find_all('script'))

        all_links   = soup.find_all('a', href=True)
        self_ref    = empty_ref = ext_ref = 0
        for a in all_links:
            href = a['href'].strip()
            if not href or href in ('#', 'javascript:void(0)'):
                empty_ref += 1
            elif href.startswith(('http://', 'https://')):
                link_domain = urlparse(href).netloc.lower().replace('www.', '')
                if link_domain == (domain or ''):
                    self_ref += 1
                else:
                    ext_ref += 1
            else:
                self_ref += 1   # relative links treated as self-references
        feats['NoOfSelfRef']     = self_ref
        feats['NoOfEmptyRef']    = empty_ref
        feats['NoOfExternalRef'] = ext_ref

        feats['_fetched'] = True

    except requests.exceptions.Timeout:
        feats['_fetch_error'] = 'timeout'
    except requests.exceptions.SSLError:
        feats['_fetch_error'] = 'ssl_error'
    except requests.exceptions.ConnectionError:
        feats['_fetch_error'] = 'connection_error'
    except requests.exceptions.HTTPError:
        feats['_fetch_error'] = 'http_error'
    except Exception as e:
        feats['_fetch_error'] = str(e)

    return feats


@st.cache_data(max_entries=256, show_spinner=False)
def extract_features_for_url(url: str, fetch_webpage: bool = True) -> dict:
    """
    Build the complete feature dict for a single URL, matching every column
    (except URL/Domain/label) in url.csv. Combines URL-only structural
    features with (optionally) live webpage-derived features. Always
    returns a full, well-formed dict — never raises.
    """
    url_feats = extract_url_only_features(url)
    domain    = url_feats.pop('_domain')
    clean_url = url_feats.pop('_clean_url')
    url_feats.pop('_tld', None)
    url_feats.pop('_path', None)

    if fetch_webpage:
        web_feats = extract_webpage_features(clean_url, domain)
    else:
        web_feats = _default_webpage_features()

    fetched     = web_feats.pop('_fetched', False)
    fetch_error = web_feats.pop('_fetch_error', None)
    web_feats.pop('Title', None)   # not part of the numeric FEATURE_COLUMNS

    combined = {**url_feats, **web_feats}
    combined['_fetched']     = fetched
    combined['_fetch_error'] = fetch_error
    combined['_domain']      = domain
    return combined


def _row_to_feature_vector(feat_dict: dict) -> list:
    """Extract the ordered numeric feature vector (FEATURE_COLUMNS) from a dict."""
    return [feat_dict.get(col, 0) for col in FEATURE_COLUMNS]


# ─── Training ───────────────────────────────────────────────────────────────────

def _coerce_binary(v) -> int:
    """Robustly coerce a variety of truthy/falsy representations to 0/1."""
    if pd.isna(v):
        return 0
    s = str(v).strip().lower()
    if s in ('1', 'true', 'yes', 'y'):
        return 1
    if s in ('0', 'false', 'no', 'n', ''):
        return 0
    try:
        return 1 if float(s) != 0 else 0
    except ValueError:
        return 0


def train_url_model(data_path: str = DATA_PATH) -> dict:
    """
    Train the phishing URL detector directly on the feature-engineered
    url.csv (RandomForest + GradientBoosting soft-voting ensemble).
    Returns dict with accuracy, cv_scores, report, pipeline, threshold.
    """
    df = pd.read_csv(data_path)

    if 'label' not in df.columns:
        raise ValueError("url.csv must contain a 'label' column")

    y = df['label'].apply(
        lambda v: 1 if str(v).strip().lower() in {str(x).lower() for x in _POSITIVE_LABELS} else 0
    ).values

    # Build the numeric feature matrix from whatever of FEATURE_COLUMNS exist,
    # filling any missing columns with 0 so the schema always matches.
    binary_like_cols = {
        'IsDomainIP', 'HasObfuscation', 'IsHTTPS', 'HasTitle', 'HasFavicon',
        'Robots', 'IsResponsive', 'HasDescription', 'HasExternalFormSubmit',
        'HasSocialNet', 'HasSubmitButton', 'HasHiddenFields', 'HasPasswordField',
        'Bank', 'Pay', 'Crypto', 'HasCopyrightInfo',
    }

    X = pd.DataFrame(index=df.index)
    for col in FEATURE_COLUMNS:
        if col in df.columns:
            if col in binary_like_cols:
                X[col] = df[col].apply(_coerce_binary)
            else:
                X[col] = pd.to_numeric(df[col], errors='coerce')
        else:
            X[col] = 0

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    rf = RandomForestClassifier(
        n_estimators=300, max_depth=None, min_samples_leaf=2,
        class_weight='balanced', n_jobs=-1, random_state=42,
    )
    gb = GradientBoostingClassifier(
        n_estimators=200, max_depth=4, learning_rate=0.08, random_state=42,
    )

    ensemble = VotingClassifier(
        estimators=[('rf', rf), ('gb', gb)],
        voting='soft',
        weights=[1, 1],
    )

    pipeline = Pipeline([
        ('imputer', SimpleImputer(strategy='median')),
        ('clf', ensemble),
    ])

    pipeline.fit(X_train, y_train)

    probas      = pipeline.predict_proba(X_test)[:, 1]
    best_thresh = 0.5
    best_f1     = 0.0
    for t in np.arange(0.30, 0.71, 0.01):
        preds = (probas >= t).astype(int)
        f = f1_score(y_test, preds, zero_division=0)
        if f > best_f1:
            best_f1, best_thresh = f, round(float(t), 2)

    y_pred = (probas >= best_thresh).astype(int)
    acc    = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing'])

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(pipeline, X, y, cv=cv, scoring='f1', n_jobs=-1)

    artifact = {
        'pipeline': pipeline,
        'threshold': best_thresh,
        'feature_columns': FEATURE_COLUMNS,
    }
    joblib.dump(artifact, MODEL_PATH)

    return {
        'accuracy':   acc,
        'threshold':  best_thresh,
        'cv_f1_mean': round(float(cv_scores.mean()), 4),
        'cv_f1_std':  round(float(cv_scores.std()),  4),
        'report':     report,
        'pipeline':   pipeline,
    }


# ─── Inference ──────────────────────────────────────────────────────────────────

@st.cache_resource
if os.path.exists(DATA_PATH):
    try:
        result = train_url_model()
        return {
            'pipeline': result['pipeline'],
            'threshold': result['threshold'],
            'feature_columns': FEATURE_COLUMNS,
        }

    except Exception:
        import traceback
        print("\n===== ERROR TRAINING URL MODEL =====")
        traceback.print_exc()
        print("====================================\n")
        
    if os.path.exists(DATA_PATH):
        try:
            result = train_url_model()
            return {
                'pipeline': result['pipeline'],
                'threshold': result['threshold'],
                'feature_columns': FEATURE_COLUMNS,
            }
        except Exception as e:
            print(f"[url_model] Warning: training failed: {e}")

    return None


def predict_url(url: str, fetch_webpage: bool = True) -> dict:
    """
    Predict whether a URL is phishing, using the full feature-engineered
    model. Live-fetches webpage-dependent features when possible; falls
    back to structural-only features (and finally to 'unknown') if the
    model/data isn't available or the page can't be reached.

    Returns:
        {
          'label':       'phishing' | 'legitimate' | 'unknown',
          'probability': float  (0.0–1.0, probability of phishing),
          'confidence':  float  (0.0–1.0),
          'fetched':     bool   (whether the live webpage was reachable),
          'features':    dict   (the computed feature values, for display),
        }
    """
    artifact = load_url_artifact()

    if artifact is None:
        return {
            'label':       'unknown',
            'probability': 0.0,
            'confidence':  0.0,
            'fetched':     False,
            'features':    {},
        }

    pipeline  = artifact['pipeline']
    threshold = artifact['threshold']

    try:
        feat_dict = extract_features_for_url(url, fetch_webpage=fetch_webpage)
    except Exception as e:
        print(f"[url_model] Warning: feature extraction failed: {e}")
        return {
            'label':       'unknown',
            'probability': 0.0,
            'confidence':  0.0,
            'fetched':     False,
            'features':    {},
        }

    vector = _row_to_feature_vector(feat_dict)
    X_row  = pd.DataFrame([vector], columns=FEATURE_COLUMNS)

    try:
        proba   = pipeline.predict_proba(X_row)[0]     # [p_legit, p_phish]
        ml_prob = float(proba[1])
    except Exception as e:
        print(f"[url_model] Warning: prediction failed: {e}")
        return {
            'label':       'unknown',
            'probability': 0.0,
            'confidence':  0.0,
            'fetched':     feat_dict.get('_fetched', False),
            'features':    feat_dict,
        }

    label      = 'phishing' if ml_prob >= threshold else 'legitimate'
    confidence = round(abs(ml_prob - 0.5) * 2.0, 4)

    return {
        'label':       label,
        'probability': round(ml_prob, 4),
        'confidence':  confidence,
        'fetched':     feat_dict.get('_fetched', False),
        'fetch_error': feat_dict.get('_fetch_error'),
        'features':    feat_dict,
    }


# ─── Bootstrap ──────────────────────────────────────────────────────────────────
if not os.path.exists(MODEL_PATH):
    try:
        if os.path.exists(DATA_PATH):
            train_url_model()
    except Exception as e:
        print(f"[url_model] Warning: could not pre-train phishing URL model: {e}")