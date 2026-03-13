"""
SpamShield — Flask Backend
===========================
Serves the frontend and exposes a /analyze API endpoint.

Install:
    pip install scikit-learn pandas flask

Run:
    python backend/app.py
    then open http://localhost:5000
"""

import re
import os
import urllib.parse
import warnings
import pandas as pd
warnings.filterwarnings('ignore')

from flask import Flask, request, jsonify, send_from_directory
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

# ─────────────────────────────────────────────────────────
#  PATHS
# ─────────────────────────────────────────────────────────

BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, 'frontend')
DATASET_PATH = os.path.join(BASE_DIR, 'dataset', 'Book2.csv')

# ─────────────────────────────────────────────────────────
#  URL THREAT ANALYSIS  (same logic as urlscanner.js)
# ─────────────────────────────────────────────────────────

SUSPICIOUS_TLDS   = {'.xyz','.tk','.ml','.ga','.cf','.gq','.pw','.top','.click','.link','.download'}
PHISHING_KEYWORDS = ['login','verify','account','update','secure','bank','paypal','free',
                     'win','prize','urgent','confirm','suspend','ebay','amazon','apple']
URL_SHORTENERS    = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','rb.gy']
TRUSTED_DOMAINS   = {'google.com','youtube.com','facebook.com','twitter.com','instagram.com',
                     'amazon.com','microsoft.com','apple.com','github.com','linkedin.com',
                     'wikipedia.org','reddit.com','netflix.com','stackoverflow.com','gmail.com'}
TYPOSQUATS        = {'g00gle':'google','paypa1':'paypal','amaz0n':'amazon',
                     'faceb00k':'facebook','micros0ft':'microsoft','app1e':'apple'}


def extract_urls(text):
    pattern = re.compile(r'(https?://[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+)', re.IGNORECASE)
    return list(set(pattern.findall(text)))


def analyze_url(raw_url):
    result = {'url': raw_url, 'score': 0, 'flags': [], 'verdict': '', 'cls': 'unknown'}
    try:
        url    = raw_url if raw_url.startswith('http') else 'http://' + raw_url
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().replace('www.', '')
        lower  = url.lower()
        base   = '.'.join(domain.split('.')[-2:])

        if base in TRUSTED_DOMAINS:
            result['score'] -= 40
            result['flags'].append(f'Trusted domain: {base}')

        if parsed.scheme == 'http':
            result['score'] += 15
            result['flags'].append('No HTTPS (insecure connection)')

        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
            result['score'] += 35
            result['flags'].append('IP address instead of domain name')

        bad_tld = next((t for t in SUSPICIOUS_TLDS if domain.endswith(t)), None)
        if bad_tld:
            result['score'] += 25
            result['flags'].append(f'Suspicious TLD: {bad_tld}')

        hits = [k for k in PHISHING_KEYWORDS if k in lower]
        if hits:
            result['score'] += min(len(hits) * 10, 30)
            result['flags'].append(f'Phishing keywords: {", ".join(hits[:3])}')

        if domain.count('.') > 3:
            result['score'] += 20
            result['flags'].append(f'Excessive subdomains ({domain.count(".")} levels)')

        if len(raw_url) > 100:
            result['score'] += 10
            result['flags'].append(f'Very long URL ({len(raw_url)} chars)')

        if any(s in domain for s in URL_SHORTENERS):
            result['score'] += 20
            result['flags'].append('URL shortener — real destination hidden')

        if '@' in url:
            result['score'] += 30
            result['flags'].append('@ symbol in URL — deceptive redirect trick')

        for fake, real in TYPOSQUATS.items():
            if fake in domain:
                result['score'] += 40
                result['flags'].append(f'Possible typosquatting of "{real}"')
                break

        result['score'] = max(0, min(100, result['score']))

        if   result['score'] >= 60: result['verdict'] = 'SUSPICIOUS';    result['cls'] = 'suspicious'
        elif result['score'] >= 30: result['verdict'] = 'POTENTIALLY RISKY'; result['cls'] = 'risky'
        else:                        result['verdict'] = 'LIKELY SAFE';   result['cls'] = 'safe'

    except Exception as e:
        result['flags'].append(f'Could not parse URL: {e}')

    return result

# ─────────────────────────────────────────────────────────
#  ML MODELS  (trained once on startup)
# ─────────────────────────────────────────────────────────

def clean_text(text):
    text = re.sub(r'https?://\S+|www\.\S+', ' urltoken ', text)
    return re.sub(r'\s+', ' ', text).strip()


def build_vectorizer():
    return TfidfVectorizer(
        stop_words='english',
        lowercase=True,
        ngram_range=(1, 2),
        max_features=8000,
        sublinear_tf=True
    )


def train_models(df):
    X = [clean_text(m) for m in df['message']]
    y = df['label'].tolist()

    if len(X) < 10:
        print(f"  Warning: only {len(X)} rows — training on all data, no evaluation split.")
        X_train, y_train = X, y
    else:
        from sklearn.model_selection import train_test_split
        X_train, _, y_train, _ = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    nb = Pipeline([('tfidf', build_vectorizer()), ('clf', MultinomialNB(alpha=0.1))])
    nb.fit(X_train, y_train)

    svm = Pipeline([('tfidf', build_vectorizer()), ('clf', SVC(kernel='linear', probability=True, C=1.0, random_state=42))])
    svm.fit(X_train, y_train)

    print("  ✅ Models trained successfully.")
    return nb, svm


def classify(text, nb_model, svm_model):
    cleaned = clean_text(text)

    nb_label = nb_model.predict([cleaned])[0]
    nb_conf  = round(max(nb_model.predict_proba([cleaned])[0]) * 100, 1)

    svm_label = svm_model.predict([cleaned])[0]
    svm_conf  = round(max(svm_model.predict_proba([cleaned])[0]) * 100, 1)

    if nb_label == svm_label:
        final_label = nb_label
        final_conf  = round((nb_conf + svm_conf) / 2, 1)
        agreement   = 'Both models agree'
        agree_type  = 'agree'
    else:
        final_label = svm_label
        final_conf  = round(svm_conf * 0.72, 1)
        agreement   = 'Models disagree — SVM used as tiebreaker'
        agree_type  = 'disagree'

    return {
        'label':       final_label,
        'confidence':  final_conf,
        'agreement':   agreement,
        'agree_type':  agree_type,
        'naive_bayes': {'label': nb_label,  'confidence': nb_conf},
        'svm':         {'label': svm_label, 'confidence': svm_conf},
    }

# ─────────────────────────────────────────────────────────
#  FLASK APP
# ─────────────────────────────────────────────────────────

app = Flask(__name__, static_folder=FRONTEND_DIR)

# Train on startup
print("\nLoading dataset and training models...")
try:
    df = pd.read_csv(DATASET_PATH)
    nb_model, svm_model = train_models(df)
except FileNotFoundError:
    print(f"  ERROR: Dataset not found at {DATASET_PATH}")
    print("  Make sure dataset/Book2.csv exists.")
    exit(1)


# ── Serve frontend files ──────────────────────────────────

@app.route('/')
def index():
    return send_from_directory(FRONTEND_DIR, 'index.html')

@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory(FRONTEND_DIR, filename)


# ── API endpoint ─────────────────────────────────────────

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    POST /analyze
    Body: { "message": "your text here" }
    Returns: classification result + URL analysis as JSON
    """
    data    = request.get_json()
    message = data.get('message', '').strip()

    if not message:
        return jsonify({'error': 'No message provided'}), 400

    # ML classification
    result = classify(message, nb_model, svm_model)

    # URL analysis
    urls     = extract_urls(message)
    url_data = [analyze_url(u) for u in urls]

    return jsonify({
        'classification': result,
        'urls':           url_data
    })


# ── Optional: save feedback to dataset ───────────────────

@app.route('/feedback', methods=['POST'])
def feedback():
    """
    POST /feedback
    Body: { "message": "...", "label": "spam" or "ham" }
    Saves the correction to the dataset CSV.
    """
    global df
    data    = request.get_json()
    message = data.get('message', '').strip()
    label   = data.get('label', '').strip().lower()

    if not message or label not in ('spam', 'ham'):
        return jsonify({'error': 'Invalid input'}), 400

    new_row = pd.DataFrame({'message': [message], 'label': [label]})
    df      = pd.concat([df, new_row], ignore_index=True)
    df.to_csv(DATASET_PATH, index=False)

    return jsonify({'status': 'saved'})


if __name__ == '__main__':
    print("\n🛡️  SpamShield is running!")
    print("   Open http://localhost:5000 in your browser\n")
    app.run(debug=True, port=5000)
