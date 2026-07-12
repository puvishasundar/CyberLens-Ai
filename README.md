# CyberLens AI — Complete Deep Description

**Project by:** Puvisha S, Vidhya Priya P, Hemanthika M
**Stack:** Python · Streamlit · scikit-learn · NLTK · Plotly · OpenCV · Tesseract OCR

---

## 🛡️ What Is CyberLens AI?

CyberLens AI is a **real-time AI-powered cybersecurity intelligence platform** built to protect everyday users — especially job seekers and students — from online scams, phishing attacks, and digital fraud. It combines machine learning, natural language processing (NLP), heuristic rule engines, and computer vision into a single, beautifully designed web dashboard.

The core mission is simple: **detect digital threats before victims are harmed.** Whether the threat arrives as a suspicious WhatsApp message, a fake job offer email, a malicious URL, a fraudulent QR code, or a scam-laced PDF — CyberLens AI can scan and score it in seconds.

---

## 🎨 Visual Design & UI System

The UI has a premium **dark cyberpunk / threat-intelligence aesthetic**, inspired by real-world security dashboards and SIEM tools.

### Design Identity
- **Color palette:** Deep space navy background (`#020409`), electric cyan primary (`#00d4ff`), neon green safe (`#00ff9d`), threat red (`#ff3366`), warning amber (`#ffb340`), purple accent (`#7c3aed`)
- **Typography:** Three distinct font roles — `Orbitron` (display/scores), `Rajdhani` (headings/labels), `JetBrains Mono` (data/monospace content), plus `Inter` for body text
- **Background Effect:** An animated Matrix-style canvas (`<canvas id="cl-matrix">`) renders scrolling columns of cyan characters — Latin digits, Japanese katakana, and cybersecurity symbols — at 6% opacity, creating a live "active system" atmosphere without distracting from content
- **Glass morphism cards:** All result cards use `rgba(255,255,255,0.025)` backgrounds with subtle borders and glowing `box-shadow` effects
- **Animations:** Every result card fades in on appearance (`resultFadeIn`), badges slide in from the left (`badgeIn`), and metric cells pop up with staggered delays (`metaIn`). Threat levels have continuous pulse animations (e.g. `pulseCritical` at 1.5s for urgent red glow)

### Top Bar
A fixed header renders via an embedded HTML `<iframe>` component with:
- **Brand logo:** Animated pulsing shield icon with gradient border
- **Live ticker:** A scrolling marquee showing real-time session stats — total scans, threats found, ML engine status, and a live alert ("Fake job scams rising 340% — Stay vigilant")
- **Status pill:** A green "SYSTEMS ONLINE" badge with a pulsing dot

### Navigation
Seven navigation tabs rendered as custom HTML buttons with SVG icons: Dashboard, Analyzer, URL Scanner, QR Scanner, Company Verifier, Analytics, and About. The active tab glows cyan with an underline indicator. Navigation works via JavaScript that bridges the custom HTML component back to Streamlit's hidden button system.

---

## 📄 Pages & Features

### 1. Dashboard
The landing page displays:
- **Animated radar scanner** — three pulsing concentric rings with a sweeping radar beam around a central shield emoji, establishing the "threat monitoring" theme
- **4 live stat cards:** Total Scans, Threats Detected, Safe Scans, Critical Threats — all pulled from session state and updated in real time
- **Quick Action Grid:** Four clickable cards (AI Analyzer, URL Scanner, QR Scanner, Company Verifier) that navigate the user instantly
- **Recent Threat History feed:** A reverse-chronological live feed showing the last 8 scans with their threat level badge, scan type, risk score, and timestamp

---

### 2. AI Analyzer (Text / Image OCR / PDF)

This is the core feature, with three sub-tabs:

#### 📝 Text / Message Analysis
- Users paste any suspicious message, job offer, email, or recruiter text
- **Multilingual support banner** shows all 7 supported languages with flags
- **9 quick example buttons** — 3 English scam examples + 6 multilingual examples in Tamil, Hindi, Spanish, Telugu, Kannada, and Malayalam
- A character counter updates live as the user types
- On clicking "Analyze Threat," a 6-step animated progress bar runs through: language detection → translation → NLP analysis → pattern detection → risk scoring → report generation
- The result shows the **Language Detection Badge** (flag, language name, native script, confidence %, and whether translation was applied)
- The full result card renders with: Neural Risk Ring, Verdict Badge, Meta Grid (threat level / risk % / safety status), AI Verdict text, Suspicious Indicator chips, and Recommendations

#### 🖼️ Image (OCR) Analysis
- User uploads a PNG/JPG/BMP/TIFF image
- The image is displayed alongside a 3-step OCR progress animation
- Tesseract OCR extracts text from the image
- The extracted text is then passed through the full AI analysis pipeline
- Results show word count, character count, and the full threat result card

#### 📄 PDF Document Analysis
- User uploads a PDF file
- Shows filename, file size (KB), and page count stat cards
- Extracts up to 3,000 characters from the first few pages using `pdfplumber` (with `PyPDF2` as fallback)
- Displays a document preview (first 500 chars)
- Passes extracted text through the full AI pipeline

---

### 3. URL Scanner
- Three quick example buttons: a phishing login URL, an IP-domain URL, and a legitimate LinkedIn URL
- User enters any URL
- The URL is displayed in a styled `url-display` block before scanning
- A 4-step progress animation runs: parsing → domain reputation → phishing pattern scan → risk scoring
- Results include all URL-specific fields: HTTPS status, domain, TLD, IP-as-domain flag, URL length, suspicious keywords, typosquatting detection, known-legitimate-domain check, and trust score

---

### 4. QR Scanner
- User uploads a QR code image (PNG/JPG/BMP/GIF)
- The image is displayed with a scan-line animation overlay
- OpenCV's `QRCodeDetector` decodes the QR — with two fallback strategies: WeChatQRCode detector and a grayscale+Otsu-threshold pre-process
- If the decoded content is a URL → runs URL analysis; if it's text → runs text analysis
- The decoded content is displayed, then the full result card renders below

---

### 5. Company Verifier
- Three input fields: Company Name, Recruiter Email, Company Website
- Aggregates three separate analyses:
  - **Company name heuristics** — flags suspicious words like "overseas jobs," "guaranteed placement," "100% placement," etc.
  - **Recruiter email domain check** — detects free-mail providers (Gmail, Yahoo, Hotmail, Outlook, etc.) which legitimate companies don't use for official recruiting
  - **Website URL analysis** — runs the full URL phishing scanner
- Shows a **Trust Score meter** (0–100) as a animated progress bar
- Outputs a combined risk score (average of all three), a verdict, and tiered recommendations

---

### 6. Analytics
- Requires at least one prior scan in the session
- **4 summary stat cards** (same as Dashboard, updated live)
- **Threat Distribution Pie Chart** (Plotly donut chart) — shows the breakdown of SAFE / LOW / MEDIUM / HIGH / CRITICAL scans by count and percentage, color-coded to match the threat palette
- **Scan Category Bar Chart** — horizontal bar chart showing how many scans were done per tool (AI Analyzer, URL Scanner, OCR Scanner, etc.)
- **Scan History Table** — shows the last 20 scans with index, type, level badge, score, and timestamp; rows have hover highlight
- **Risk Score Timeline** — a Plotly line chart with area fill showing how risk scores have trended across the last 15 scans

---

### 7. About
- Animated floating shield hero with glowing drop-shadow
- **"What CyberLens Protects Against"** — 5 cards: Fake Jobs, Phishing Links, QR Scams, Fake Recruiters, Fraud PDFs
- **"How It Works"** — 4-step flow: Upload → AI Analysis → Risk Scoring → Threat Report
- **"Why This Project Matters"** — an honest, mission-driven message about the real-world problem of scam fraud targeting students and job seekers
- **"Future Vision" Roadmap** — 5 planned features actually listed in the app: a mobile-responsive application, an AI chatbot to guide users, a complete multilingual *website interface* (today only the scam-detection engine is multilingual, not the UI chrome), voice scam detection from uploaded audio, and user login with saved scan history
- Footer credits the team (Puvisha S, Vidhya Priya P, Hemanthika M) and lists the tech stack

---

## 🧠 AI / ML Engine (ml_model.py)

This is the most technically sophisticated part of the project.

### Architecture: Dual TF-IDF + Soft-Voting Ensemble

**Feature Extraction:**
- **Word n-gram TF-IDF** (1–3 grams, 8,000 features) — captures phrases like "pay registration fee," "guaranteed income," "no interview"
- **Character n-gram TF-IDF** (3–5 char grams, 4,000 features) — catches obfuscated text like "j0b," "fr33," character-level typos used to evade keyword filters
- Both are merged via `FeatureUnion` into a single 12,000-dimensional feature vector

**Classifiers (Soft Voting Ensemble):**
- **Logistic Regression** (weight: 3) — the primary classifier, proven strongest on short text; C=2.0, balanced class weights
- **SGDClassifier** with modified Huber loss + Isotonic calibration (weight: 2) — a fast stochastic variant with different inductive bias, provides ensemble diversity
- **Random Forest** (200 trees, depth 12, weight: 2) — adds non-linear decision capacity

**Training Pipeline:**
1. Data loaded from `scam.csv` if present (primary, user-supplied dataset), falling back to the legacy `sample_data.csv` if it isn't
2. Text preprocessed: lowercased, URLs → `URLTOKEN`, money amounts (`$` or `Rs`) → `MONEYTOKEN`, percentages → `PERCENTTOKEN`, long digit strings → `PHONETOKEN`, email addresses → `EMAILTOKEN`, stop words removed, lemmatization applied
3. 80/20 stratified train/test split
4. Threshold tuning: instead of a fixed 0.5 cutoff, the best threshold (swept 0.30–0.70) is found by maximizing F1 score on the held-out test set
5. 5-fold stratified cross-validation to report reliable CV F1 scores
6. Model, ensemble, and tuned threshold are saved together as one dict (`{'pipeline':..., 'threshold':...}`) to `scam_detector.pkl` via `joblib` — there's no separate vectorizer file; the TF-IDF vectorizers live inside the saved pipeline
7. If no `.pkl` artifact exists on startup but a CSV is present, the app trains automatically on first load

**Inference:**
- Text is preprocessed → dual TF-IDF transform → ensemble `predict_proba`
- **Rule-based pre-filter** runs 8 regex patterns for high-confidence scam signals (e.g., "pay ... fee/now/urgent," "wire transfer/bitcoin ... send/pay," "send/share ... OTP/Aadhaar/PAN/bank details," "earn $X/day," "limited seats/act fast"). Hits are saturating-scaled into a `rule_score` (0.0–1.0) via `1 − 1/(1 + hits×1.3)` — 1 hit ≈ 0.57, 2 hits ≈ 0.72, 3+ hits ≈ 0.92+
- If `rule_score ≥ 0.70` (2+ strong rule hits): final probability = `0.35 × ML + 0.65 × rules` — rules dominate for novel scam text the ML model hasn't seen
- Otherwise: `0.50 × ML + 0.50 × rules` — an even split
- The scam/legitimate label is decided by comparing this blended probability against a **per-model tuned threshold** (found during training, not a fixed 0.5)
- Confidence is computed as `|blended_probability − 0.5| × 2` — giving a full 0–100% range, avoiding the "artificially low confidence" problem of naive `max(p, 1-p)`

**Feature Importance:**
- `get_feature_importance()` extracts the top-N TF-IDF scoring tokens for any input text, providing interpretability ("why did the model flag this?")

---

## 📊 Risk Scoring System (utils.py)

### Keyword Lexicon (SCAM_KEYWORDS)
A large, manually curated dictionary of **675 weighted scam-signal phrases** (1–5 points each) — not a small starter list. Highlights:
- **Weight 5:** high-certainty fraud phrases like sharing OTP/Aadhaar/bank details, placement/offer-letter fees
- **Weight 3–4:** payment/registration/processing fees, wire transfer, bitcoin, "verify your account," KYC update, guaranteed income, "no interview," account-suspension language
- **Weight 1–2:** softer signals like "work from home," "urgent," "click here"
- Heavy coverage of India-specific fraud: OTP scams, KYC/Aadhaar/PAN phishing, UPI scams, "digital arrest"/fake CBI notices, fake electricity-bill threats, fake customs/parcel-fee scams, fake scholarship fees

Two supporting lists reduce false positives:
- **`NEGATION_WORDS` / `SAFE_PHRASES`** — phrases like "no registration fee," "we never ask for OTP," or "official website" are stripped or checked as negating context before a keyword hit counts
- **`SAFE_KEYWORDS`** (~110 everyday/institutional phrases like "meeting," "invoice," "student portal," "google meet") dampen the score when only weak (weight ≤2) keyword hits accompany them, so routine emails aren't mis-flagged

**Combination bonuses:** on top of individual keyword weights, 25 hand-picked keyword *pairs* (e.g. `"registration fee" + "urgent"`, `"kyc" + "account blocked"`, `"offer letter" + "fee"`) each add an extra 5–7 points when both phrases co-occur — because real scams are far more reliably identified by combinations of signals than any single word.

### Risk Level Scale (exact thresholds from `compute_risk_level`)

| Score | Level | Color |
|-------|-------|-------|
| 0–20 | SAFE | 🟢 Green |
| 21–40 | LOW | 🔵 Blue |
| 41–60 | MEDIUM | 🟡 Amber |
| 61–80 | HIGH | 🟠 Orange |
| 81–100 | CRITICAL | 🔴 Red |

### Score Normalization
The raw keyword score is normalized linearly against a ceiling of 20 points (`min(raw/20, 1.0) × 100`), capped at 100.

### Final Blended Score
The text analyzer dynamically re-weights the ML model vs. the keyword score depending on how strong the keyword signal is, rather than using one fixed ratio:
- If normalized keyword score ≥ 60 → **30% ML / 70% keywords** (keywords dominate when the lexicon hit is very strong)
- If normalized keyword score ≤ 10 → **70% ML / 30% keywords** (ML dominates when there's little lexical evidence)
- Otherwise → **45% ML / 55% keywords** (balanced middle ground)

---

## 🤖 URL Phishing ML Model (url_model.py)

Separate from the text scam model, CyberLens AI trains a **second, dedicated ML classifier purely for URL structure** — it never has to fetch the page to make this prediction.

**Features extracted per URL (11 total):** `url_length`, `num_dots`, `has_https`, `has_ip` (IPv4 **and** IPv6-aware), `num_subdirs`, `num_params`, `suspicious_words` (count of hits against a 39-word phishing-lexicon list: login, verify, banking, webscr, wallet, crypto, urgent, etc.), `tld_risk`, `special_char_count`, `digits_count`, and Shannon `entropy` of the raw URL string.

**`tld_risk` is learned, not hand-coded:** during training, each TLD's historical phishing rate is computed directly from the labeled dataset (`groupby('tld')['y'].mean()`) and stored in a `tld_risk_map`; unseen TLDs fall back to the dataset's overall positive-class prior.

**Model:** soft-voting ensemble of a `RandomForestClassifier` (300 trees) and a `GradientBoostingClassifier` (200 estimators, depth 4), wrapped in a pipeline with median imputation. Trained with the same 80/20 stratified split + F1-maximizing threshold sweep + 5-fold CV pattern as the text model, and saved to `phishing_url_detector.pkl`.

**Inference:** `predict_url()` extracts the 11 features, runs them through the pipeline, and returns a `phishing`/`legitimate` label plus probability and confidence — deliberately **without** fetching the live page (page fetching/content-scam-phrase scanning is handled separately upstream by `analyzer.analyse_webpage_content()` so the app never issues two HTTP requests for one scan).

**Interpretability:** `get_feature_importance_url()` mirrors the text model's explainability — it multiplies the ensemble's averaged `feature_importances_` by this URL's own normalized feature values, so the app can show *which specific features* (e.g. high entropy, many suspicious words) drove a given verdict.

---

## 🌐 URL Heuristic Risk Analysis (utils.py — `analyse_url`)

Independently of the ML model above, every URL also runs through a 12-point rule-based scorer that produces flags and a heuristic score (capped 0–100):

| Signal | Score added |
|---|---|
| Not HTTPS | +25 |
| IP address used as the domain | +35 |
| URL longer than 75 characters | +12 |
| Each phishing-style keyword matched in the URL (from a 33-word list: `login`, `verify`, `secure`, `banking`, `crypto`, `refund`, `giving`, etc.) | +12 per match |
| Risky TLD (`.xyz`, `.top`, `.click`, `.loan`, `.pw`, `.gq`, `.cf`, `.tk`, `.ml`, `.ga`, `.win`, `.bid`, `.review`, `.country`, `.work`) | tier weight (3 or 4) × 10 |
| Typosquatting a known brand (e.g. `paypa1.com`) | +40 |
| `@` symbol in the URL | +30 |
| Percent-encoded characters | +8 |
| Redirection query parameter (`redirect=`, `url=`, `next=`, etc.) | +15 |
| High digit ratio (>15% of characters are digits) | +10 |
| More than 8 special characters | +12 |
| High Shannon entropy (>4.5) | +10 |
| Known link shortener (bit.ly, tinyurl.com, cutt.ly, etc.) | +15 |
| Domain matches a known-legitimate list (Google, Microsoft, LinkedIn, Infosys, TCS, Flipkart, etc.) | −60 |

*(Note: bare brand names like "paypal" or "google" are deliberately **not** in the keyword list — matching them would flag the legitimate domains themselves. Brand impersonation is instead caught by the dedicated typosquatting check above.)*

The final per-URL risk score used in the app is a **hybrid** of this heuristic score, the URL ML model's probability, the text-scam-model's probability on the page's fetched content, and a bonus for any scam phrases found on the live page — combined and then floored at a minimum ("false-safe floor") whenever the phishing ML model or the page-content model is highly confident, so a low heuristic score alone can never mask a page the AI models are confident is malicious.



## 🌍 Multilingual Engine (language_utils.py)

CyberLens AI can detect and analyze content in 7 languages:

| Code | Language | Script |
|------|----------|--------|
| `ta` | Tamil | தமிழ் |
| `en` | English | Latin |
| `te` | Telugu | తెలుగు |
| `ml` | Malayalam | മലയാളം |
| `kn` | Kannada | ಕನ್ನಡ |
| `hi` | Hindi | हिन्दी |
| `es` | Spanish | Español |

### Detection Strategy (3-layer):
1. **Unicode block heuristic** — counts codepoints per Indic script range; if a script accounts for ≥60% of script characters, it's identified with 97% confidence. Zero-dependency, instant.
2. **langdetect library** — offline ML-based detector for Latin-script languages (English vs Spanish differentiation)
3. **Latin script fallback** — checks for common Spanish function words (`de`, `la`, `el`, `que`, etc.); if 3+ markers found → Spanish; otherwise → English

### Translation Strategy (2-layer):
1. **googletrans** (unofficial Google Translate API, no key required)
2. **deep-translator** as fallback
3. If both fail → original text is passed through unchanged (analysis still runs)

After translation, the UI shows a language badge with the flag, language name, native name, confidence %, and which translation backend was used. The user can expand to see both the original text and the English translation used for analysis.

---

## 🗂️ File Architecture

| File | Role |
|------|------|
| `app.py` | Streamlit frontend — all UI, pages, navigation, result rendering (~2,180 lines) |
| `analyzer.py` | High-level analysis wrappers for text, URL, QR, OCR, PDF, company (~915 lines) |
| `ml_model.py` | Text scam-classifier: training, inference, preprocessing, rule engine, feature importance (~370 lines) |
| `url_model.py` | URL phishing-classifier: feature extraction, training, inference, feature importance (~470 lines) |
| `utils.py` | Keyword lexicon, risk scoring, heuristic URL analysis, recruiter/company heuristics (~695 lines) |
| `language_utils.py` | Language detection, translation, language badge HTML |
| `styles.css` | Custom CSS — glass morphism, animations, color variables, component styles |
| `scam_detector.pkl` | Trained artifact for the **text** model (TF-IDF pipeline + ensemble + tuned threshold, all in one dict) |
| `phishing_url_detector.pkl` | Trained artifact for the **URL** model (RF+GB ensemble + tuned threshold + learned TLD-risk map) — generated by `url_model.py`, expected alongside the text model but not part of this upload |
| `scam.csv` / `sample_data.csv` | Training data for the text model — `scam.csv` used if present, `sample_data.csv` as legacy fallback |
| `url.csv` | Training data for the URL model |
| `requirements.txt` | All Python dependencies |
| `packages.txt` | System package dependency (`tesseract-ocr`) required for OCR on Streamlit Cloud |

---

## ⚙️ Tech Stack Summary

- **Framework:** Streamlit (Python web app framework)
- **ML/NLP:** scikit-learn (TF-IDF, Logistic Regression, SGD, Random Forest, VotingClassifier, CalibratedClassifierCV), NLTK (stopwords, lemmatization)
- **Computer Vision:** OpenCV (QR decoding), Pillow (image processing), pytesseract (OCR)
- **PDF Parsing:** pdfplumber (primary), PyPDF2 (fallback)
- **Visualization:** Plotly (gauges, pie charts, bar charts, line charts)
- **Language:** langdetect, googletrans, deep-translator
- **Persistence:** joblib (model serialization)
- **URL Analysis:** Python's built-in `urllib.parse` + custom regex heuristics

---

## 🎯 What Makes This Project Stand Out

1. **Multilingual-first design** — most scam detectors are English-only; CyberLens handles Tamil, Hindi, Telugu, Kannada, Malayalam, and Spanish natively, targeting the Indian subcontinent where these scams are most prevalent

2. **Multi-modal threat detection** — the same AI pipeline handles raw text, images (via OCR), PDFs, URLs, QR codes, and company profiles — all in one unified interface

3. **Two independently-trained ML models, not one** — a dual-TF-IDF ensemble for text/message content, and a completely separate 11-feature structural ensemble (Random Forest + Gradient Boosting) purely for URL phishing detection, each with its own F1-tuned decision threshold

4. **Interpretable AI** — the system doesn't just output a score; it shows which specific keywords, TF-IDF features, URL structural features, and rule patterns contributed to the verdict

4. **Ensemble + rule hybrid** — combining a soft-voting ML ensemble with regex-based scam rules means the model catches both statistically-learned patterns AND novel, unseen scam variants

5. **Production-quality UI** — the animated Matrix canvas, Neural Risk Ring SVG, live ticker, color-coded threat levels with pulse animations, and dark cybersecurity aesthetic make this feel like a real professional security tool, not a student project

6. **India-specific threat intelligence** — the keyword lexicon includes OTP fraud, Aadhaar/PAN phishing, UPI scams, fake placement fees, and KYC fraud — threats that are specifically common in India but underrepresented in Western security tools

---

*CyberLens AI was built to be a real, working tool that makes advanced cybersecurity accessible to everyone.*
