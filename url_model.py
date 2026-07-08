# url_model.py — CyberLens AI
# Phishing URL detection pipeline (separate from the text scam model in ml_model.py)
#
# Trained from url.csv, expected columns:
#   url   — the raw URL string
#   label — 'phishing' / 'malicious' / 'bad' / 1  → positive class
#           'legitimate' / 'safe' / 'good' / 0    → negative class
#
# Design mirrors ml_model.py so the two pipelines stay consistent and easy to
# maintain, but is intentionally lighter-weight since URLs are short strings
# without natural-language structure:
#   • Character n-gram TF-IDF (3-6) — captures token/domain/path obfuscation
#   • Handful of structural numeric features (length, dots, digits, etc.)
#   • Soft-voting ensemble: LogisticRegression + SGDClassifier
#   • Threshold tuned via precision-recall curve (maximise F1)
#   • Falls back gracefully to the existing utils.analyse_url heuristic when
#     no model/data is available, so analyzer.py never breaks.

import os
import re
import joblib
import numpy as np
import pandas as pd
import streamlit as st

from urllib.parse import urlparse
from scipy.sparse import hstack, csr_matrix

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model            import LogisticRegression, SGDClassifier
from sklearn.calibration             import CalibratedClassifierCV
from sklearn.ensemble                import VotingClassifier
from sklearn.model_selection         import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics                 import accuracy_score, classification_report, f1_score
from sklearn.base                    import BaseEstimator, TransformerMixin

# ─── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'phishing_url_detector.pkl')
DATA_PATH  = os.path.join(BASE_DIR, 'url.csv')

_POSITIVE_LABELS = {'phishing', 'malicious', 'bad', 'scam', 'fraud', 'unsafe', '1', 1, True}


# ─── Structural feature extraction ─────────────────────────────────────────────

def _structural_features(url: str) -> list:
    """Small set of numeric/structural signals extracted from a raw URL."""
    u = (url or '').strip()
    try:
        parsed = urlparse(u if u.startswith(('http://', 'https://')) else 'http://' + u)
    except Exception:
        parsed = None

    domain = (parsed.netloc if parsed else '').lower()
    path   = (parsed.path if parsed else '')

    return [
        len(u),
        u.count('.'),
        u.count('-'),
        u.count('@'),
        u.count('_'),
        u.count('%'),
        u.count('/'),
        sum(ch.isdigit() for ch in u),
        1 if u.lower().startswith('https://') else 0,
        1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}', domain) else 0,
        len(domain),
        len(path),
        domain.count('.'),
        1 if '@' in u else 0,
        1 if len(u) > 75 else 0,
    ]


class StructuralFeaturizer(BaseEstimator, TransformerMixin):
    """Turns raw URL strings into a sparse matrix of structural features."""
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        feats = np.array([_structural_features(u) for u in X], dtype=float)
        return csr_matrix(feats)


@st.cache_data(max_entries=512)
def preprocess_url(url: str) -> str:
    """Light normalisation before char n-gram vectorisation."""
    if not isinstance(url, str):
        url = str(url)
    u = url.strip().lower()
    if not u.startswith(('http://', 'https://')):
        u = 'http://' + u
    return u


# ─── Training ───────────────────────────────────────────────────────────────────

def train_url_model(data_path: str = DATA_PATH) -> dict:
    """
    Train char-ngram TF-IDF + structural-feature ensemble for phishing URL
    detection. Returns dict with accuracy, cv_scores, report, pipeline, threshold.
    """
    df = pd.read_csv(data_path)
    url_col   = 'url' if 'url' in df.columns else df.columns[0]
    label_col = 'label' if 'label' in df.columns else df.columns[-1]
    df = df.dropna(subset=[url_col, label_col])

    urls = df[url_col].astype(str).apply(preprocess_url).values
    y    = df[label_col].apply(
        lambda v: 1 if str(v).strip().lower() in _POSITIVE_LABELS else 0
    ).values

    X_train, X_test, y_train, y_test = train_test_split(
        urls, y, test_size=0.2, random_state=42, stratify=y
    )

    char_tfidf = TfidfVectorizer(
        ngram_range=(3, 6),
        max_features=6000,
        sublinear_tf=True,
        min_df=2,
        analyzer='char_wb',
    )

    lr = LogisticRegression(
        C=2.0, max_iter=1000, class_weight='balanced',
        solver='lbfgs', random_state=42,
    )
    sgd_base = SGDClassifier(
        loss='modified_huber', alpha=0.001, max_iter=1000,
        class_weight='balanced', random_state=42,
    )
    sgd = CalibratedClassifierCV(sgd_base, cv=3, method='isotonic')

    ensemble = VotingClassifier(
        estimators=[('lr', lr), ('sgd', sgd)],
        voting='soft',
        weights=[1, 1],
    )

    # Structural features + TF-IDF are combined manually (fit_transform on
    # train, transform on test) rather than via FeatureUnion so we can keep
    # both a sklearn Pipeline-compatible object AND a lightweight predict path.
    from sklearn.pipeline import Pipeline, FeatureUnion

    pipeline = Pipeline([
        ('features', FeatureUnion([
            ('char',       char_tfidf),
            ('structural', StructuralFeaturizer()),
        ])),
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
    cv_scores = cross_val_score(pipeline, urls, y, cv=cv, scoring='f1', n_jobs=-1)

    artifact = {'pipeline': pipeline, 'threshold': best_thresh}
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
def load_url_artifact():
    """Load (or train-and-save) the phishing URL ML artifact."""
    if os.path.exists(MODEL_PATH):
        try:
            artifact = joblib.load(MODEL_PATH)
            if not isinstance(artifact, dict):
                artifact = {'pipeline': artifact, 'threshold': 0.5}
            return artifact
        except Exception:
            pass

    if os.path.exists(DATA_PATH):
        try:
            result = train_url_model()
            return {'pipeline': result['pipeline'], 'threshold': result['threshold']}
        except Exception as e:
            print(f"[url_model] Warning: training failed: {e}")

    return None


@st.cache_data(max_entries=256)
def predict_url(url: str) -> dict:
    """
    Predict whether a URL is phishing.

    Returns:
        {
          'label':       'phishing' | 'legitimate' | 'unknown',
          'probability': float  (0.0–1.0, probability of phishing),
          'confidence':  float  (0.0–1.0),
        }
    """
    artifact = load_url_artifact()

    if artifact is None:
        # No model available — analyzer.py's existing utils.analyse_url
        # heuristic remains the sole signal, so behaviour is unchanged.
        return {
            'label':       'unknown',
            'probability': 0.0,
            'confidence':  0.0,
        }

    pipeline  = artifact['pipeline']
    threshold = artifact['threshold']

    clean   = preprocess_url(url)
    proba   = pipeline.predict_proba([clean])[0]     # [p_legit, p_phish]
    ml_prob = float(proba[1])

    label      = 'phishing' if ml_prob >= threshold else 'legitimate'
    confidence = round(abs(ml_prob - 0.5) * 2.0, 4)

    return {
        'label':       label,
        'probability': round(ml_prob, 4),
        'confidence':  confidence,
    }


# ─── Bootstrap ──────────────────────────────────────────────────────────────────
if not os.path.exists(MODEL_PATH):
    try:
        if os.path.exists(DATA_PATH):
            train_url_model()
    except Exception as e:
        print(f"[url_model] Warning: could not pre-train phishing URL model: {e}")
