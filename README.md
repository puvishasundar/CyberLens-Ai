# CyberLens AI — Complete Deep Description

**Project by:** Puvisha, Vidhya, Hemanthika  
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
- **"Future Vision" Roadmap** — 6 planned features including VirusTotal API integration, email header analysis, BERT model upgrade, PWA mobile app, Telegram/Slack bot, and the already-live multilingual detection (marked ✅)
- Footer credits the team and lists the tech stack

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
1. Data loaded from `sample_data.csv` (text + label columns)
2. Text preprocessed: lowercased, URLs → `URLTOKEN`, money amounts → `MONEYTOKEN`, phone numbers → `PHONETOKEN`, email addresses → `EMAILTOKEN`, stop words removed, lemmatization applied
3. 80/20 stratified train/test split
4. Threshold tuning: instead of a fixed 0.5 cutoff, the best threshold (0.30–0.71) is found by sweeping and maximizing F1 score on the test set
5. 5-fold stratified cross-validation to report reliable CV F1 scores
6. Model and threshold saved as a single dict to `scam_detector.pkl` via `joblib`

**Inference:**
- Text is preprocessed → dual TF-IDF transform → ensemble predict_proba
- **Rule-based pre-filter** runs 8 regex patterns for high-confidence scam signals (e.g., "pay fee within 24 hours," "send OTP," "earn $5000/day work from home"). Each hit adds to a sigmoid-scaled `rule_score` (0.0–1.0)
- If `rule_score ≥ 0.70` (strong rule signal): final prob = `0.40 × ML + 0.60 × rules` — rules dominate for novel scam text the model hasn't seen
- Otherwise: `0.60 × ML + 0.40 × rules` — balanced blend
- Confidence is computed as `distance from 0.5 × 2` — giving a full 0–100% range, avoiding the "artificially low confidence" problem of naive `max(p, 1-p)`

**Feature Importance:**
- `get_feature_importance()` extracts the top-N TF-IDF scoring tokens for any input text, providing interpretability ("why did the model flag this?")

---

## 📊 Risk Scoring System (utils.py)

### Keyword Lexicon (SCAM_KEYWORDS)
A manually curated dictionary of 80+ scam signals with weighted scores (1–5):
- **Weight 5:** `send bank details`, `share OTP`, `placement fee`, `offer letter fee`, `send Aadhaar`
- **Weight 4:** `payment required`, `registration fee`, `wire transfer`, `bitcoin`, `verify your account`, `KYC update`, `guaranteed income`, `no interview`, `account suspended`
- **Weight 3:** `urgent`, `limited offer`, `lottery`, `you have won`, `bitcoin`, `guaranteed`
- **Weight 1–2:** `work from home`, `confidential`, `suspicious activity`, `click here`
- Includes India-specific fraud signals: OTP scams, KYC fraud, Aadhaar/PAN card phishing, job placement fees, UPI scams

### Risk Level Scale
| Score | Level | Color |
|-------|-------|-------|
| 0–19 | SAFE | 🟢 Green |
| 20–39 | LOW | 🔵 Blue |
| 40–64 | MEDIUM | 🟡 Amber |
| 65–84 | HIGH | 🟠 Orange |
| 85–100 | CRITICAL | 🔴 Red |

### Score Normalization
Raw keyword scores are normalized using a concave power curve (`ratio^0.7`) with a ceiling of 50, so moderate scam texts land in MEDIUM/HIGH rather than being incorrectly pushed to CRITICAL.

### Final Blended Score
`0.55 × (ML probability × 100) + 0.45 × (normalized keyword score)`

---

## 🌐 URL Phishing Analysis (utils.py)

For every URL scanned, the system checks:
- **HTTPS:** Missing HTTPS adds +25 risk points
- **IP-as-domain:** Using a raw IP address (e.g. `192.168.1.1`) adds +35 (near-certain malicious)
- **URL length:** Over 75 characters adds +12
- **Phishing keywords in URL:** Words like `login`, `verify`, `secure`, `account`, `paypal`, `microsoft` each add +8
- **Suspicious TLD:** `.xyz`, `.top`, `.click`, `.loan`, `.pw`, `.tk` etc. each add weighted risk (4×8 = +32 for worst TLDs)
- **Typosquatting detection:** If the URL contains a known brand's core name but isn't the real domain (e.g. `paypa1.com` instead of `paypal.com`) → +35
- **Known legitimate domain:** Matching Google, Microsoft, LinkedIn, Infosys, TCS, etc. → subtract 40

---

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
| `app.py` | Streamlit frontend — all UI, pages, navigation, result rendering (~800 lines) |
| `analyzer.py` | High-level analysis wrappers for text, URL, QR, OCR, PDF, company |
| `ml_model.py` | ML training, inference, preprocessing, rule engine, feature importance |
| `utils.py` | Keyword lexicon, risk scoring, URL analysis, recruiter/company heuristics |
| `language_utils.py` | Language detection, translation, language badge HTML |
| `styles.css` | Custom CSS — glass morphism, animations, color variables, component styles |
| `scam_detector.pkl` | Trained model artifact (pipeline + optimal threshold) |
| `vectorizer.pkl` | Saved TF-IDF vectorizer |
| `sample_data.csv` | Training dataset (text + scam/legitimate labels) |
| `requirements.txt` | All Python dependencies |

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

3. **Interpretable AI** — the system doesn't just output a score; it shows which specific keywords, TF-IDF features, URL flags, and rule patterns contributed to the verdict

4. **Ensemble + rule hybrid** — combining a soft-voting ML ensemble with regex-based scam rules means the model catches both statistically-learned patterns AND novel, unseen scam variants

5. **Production-quality UI** — the animated Matrix canvas, Neural Risk Ring SVG, live ticker, color-coded threat levels with pulse animations, and dark cybersecurity aesthetic make this feel like a real professional security tool, not a student project

6. **India-specific threat intelligence** — the keyword lexicon includes OTP fraud, Aadhaar/PAN phishing, UPI scams, fake placement fees, and KYC fraud — threats that are specifically common in India but underrepresented in Western security tools

---

*CyberLens AI was built to be a real, working tool that makes advanced cybersecurity accessible to everyone.*
