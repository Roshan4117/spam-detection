# 🛡️ SpamShield — AI Spam & Phishing Detector

> Dual-model ML spam classifier with real-time URL threat analysis.  
> Built with **Support Vector Machine (SVM)** + **Naïve Bayes** ensemble and a 10-factor URL scanner.

---

## 📁 Project Structure

```
spam-detector-project/
├── frontend/
│   ├── index.html              ← Landing page
│   ├── css/
│   │   └── style.css           
│   ├── js/
│   │   ├── main.js             ← Index page interactions
│   │   ├── classifier.js       ← Simulated SVM + Naïve Bayes 
│   │   ├── urlscanner.js       ← 10-factor URL threat analysis
│   │   └── chatbot.js          ← Chat UI controller
│   └── pages/
│       ├── chatbot.html        ← Main detector interface
│       ├── about.html          ← How it works
│       └── registration.html   ← Login / Register
├── backend/
│   ├── spam_detector.py        ← Python CLI with real trained models
│   └── requirements.txt
├── dataset/
│   └── Book2.csv               ← spam/ham CSV 
├── docs/
│   └── screenshots/            
└── README.md
```

---

## 🚀 Quick Start

### Frontend (no setup needed)
Just open `frontend/index.html` in your browser — it works without a server.

### Backend (Python CLI with real ML models)
```bash
# Install dependencies (just two packages, no NLTK needed!)
pip install scikit-learn pandas

# Place your dataset at dataset/Book2.csv
# (CSV must have columns: message, label — labels are "spam" or "ham")

# Run the detector
python backend/spam_detector.py

# Custom CSV path
python backend/spam_detector.py --csv path/to/your/dataset.csv
```

---

## 🤖 How It Works

### ML Ensemble
| Model | Algorithm | Strength |
|-------|-----------|----------|
| Naïve Bayes | MultinomialNB (α=0.1) | Fast, keyword-driven, probabilistic |
| SVM | Linear kernel SVC (C=1.0) | Maximum-margin, better generalization |

Both models are trained on **TF-IDF bigram features**. Results are ensemble-voted:
- If both **agree** → average confidence
- If they **disagree** → SVM wins as tiebreaker (reduced confidence shown)

### URL Threat Scanner (10 checks)
| Check | Risk Points |
|-------|-------------|
| IP address instead of domain | +35 |
| Typosquatting detected | +40 |
| `@` symbol in URL | +30 |
| Suspicious TLD (.xyz, .tk, .ml…) | +25 |
| Excessive subdomains (>3 levels) | +20 |
| URL shortener | +20 |
| Phishing keywords in URL | +10 each |
| No HTTPS | +15 |
| Very long URL (>100 chars) | +10 |
| Recognized trusted domain | −40 |

**Verdicts:** 🔴 SUSPICIOUS (≥60) · 🟡 RISKY (≥30) · 🟢 SAFE (<30)

---

## 📊 Dataset Format

Your `Book2.csv` must have exactly these two columns:

```csv
message,label
"Congratulations! You've won a prize. Click here to claim!",spam
"Hi team, please find the attached report for Q3.",ham
```

---

## 🛠️ Tech Stack

**Backend:** Python 3.11+ · scikit-learn · NLTK · pandas  
**Frontend:** Vanilla HTML/CSS/JS (zero dependencies)  
**Design:** Dark terminal/cyberpunk aesthetic · CSS custom properties · Google Fonts (Syne + DM Mono)

---

## 📸 Screenshots
Add screenshots to `docs/screenshots/` and reference them here.

---

## 📄 License
MIT — free to use, modify, and distribute.
