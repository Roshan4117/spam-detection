"""
SpamShield Backend — spam_detector.py
======================================
Spam classifier using SVM + Naive Bayes ensemble + URL threat analysis.

No NLTK needed! Uses only scikit-learn's built-in tokenizer.

Install:
    pip install scikit-learn pandas

Run:
    python spam_detector.py
    python spam_detector.py --csv path/to/your/dataset.csv
"""

import re
import sys
import random
import argparse
import urllib.parse
import warnings
import pandas as pd
warnings.filterwarnings('ignore')

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.pipeline import Pipeline

# ─────────────────────────────────────────────────────────
#  URL THREAT ANALYSIS
# ─────────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {'.xyz', '.tk', '.ml', '.ga', '.cf', '.gq',
                   '.pw', '.top', '.click', '.link', '.download'}

PHISHING_KEYWORDS = ['login', 'verify', 'account', 'update', 'secure',
                     'bank', 'paypal', 'free', 'win', 'prize', 'urgent',
                     'confirm', 'suspend', 'ebay', 'amazon', 'apple']

URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl',
                  'ow.ly', 'is.gd', 'buff.ly', 'rb.gy']

TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
    'instagram.com', 'amazon.com', 'microsoft.com', 'apple.com',
    'github.com', 'linkedin.com', 'wikipedia.org', 'reddit.com',
    'netflix.com', 'stackoverflow.com', 'gmail.com'
}

TYPOSQUATS = {
    'g00gle': 'google', 'paypa1': 'paypal', 'amaz0n': 'amazon',
    'faceb00k': 'facebook', 'micros0ft': 'microsoft', 'app1e': 'apple'
}


def extract_urls(text):
    """Pull all URLs out of a block of text."""
    pattern = re.compile(
        r'(https?://[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+)',
        re.IGNORECASE
    )
    return list(set(pattern.findall(text)))


def analyze_url(raw_url):
    """
    Score a URL across 10 risk factors.
    Returns a dict with score (0-100), flags, and a verdict.
    """
    result = {'url': raw_url, 'score': 0, 'flags': [], 'verdict': ''}

    try:
        url    = raw_url if raw_url.startswith('http') else 'http://' + raw_url
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().replace('www.', '')
        lower  = url.lower()
        base   = '.'.join(domain.split('.')[-2:])

        # Trusted domain reduces score
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

        if   result['score'] >= 60: result['verdict'] = '🔴 SUSPICIOUS / LIKELY FAKE'
        elif result['score'] >= 30: result['verdict'] = '🟡 POTENTIALLY RISKY'
        else:                        result['verdict'] = '🟢 LIKELY SAFE'

    except Exception as e:
        result['flags'].append(f'Could not parse URL: {e}')
        result['verdict'] = 'UNKNOWN'

    return result


# ─────────────────────────────────────────────────────────
#  TEXT CLEANING  (scikit-learn handles the rest)
# ─────────────────────────────────────────────────────────

def clean_text(text):
    """
    Minimal cleaning — replace URLs with a token so the model
    learns that URLs are a spam signal.
    scikit-learn's TfidfVectorizer handles everything else:
    lowercasing, tokenizing, stop word removal.
    """
    text = re.sub(r'https?://\S+|www\.\S+', ' urltoken ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


# ─────────────────────────────────────────────────────────
#  MODEL TRAINING
# ─────────────────────────────────────────────────────────

def build_vectorizer():
    """
    TfidfVectorizer with scikit-learn's built-in English stop words.
    - stop_words='english'  removes words like 'the', 'is', 'and'
    - ngram_range=(1, 2)    catches single words AND two-word phrases
    - sublinear_tf=True     stops very common words from dominating
    No NLTK download required.
    """
    return TfidfVectorizer(
        stop_words='english',
        lowercase=True,
        ngram_range=(1, 2),
        max_features=8000,
        sublinear_tf=True
    )


def train_models(df):
    """Train Naive Bayes and SVM, print evaluation, return both models."""

    X = [clean_text(m) for m in df['message']]
    y = df['label'].tolist()

    # Need at least 10 rows for a meaningful train/test split.
    # If the dataset is smaller we skip evaluation and train on everything.
    if len(X) < 10:
        print("Warning: Only {len(X)} rows in dataset. Add more messages to Book2.csv for better accuracy.")
        print("  Training on all available data (skipping evaluation).")
        X_train, X_test, y_train, y_test = X, X, y, y
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

    # Pipeline = vectorizer + classifier in one object
    # This makes it easy to call .predict() with raw text directly
    nb_pipeline = Pipeline([
        ('tfidf', build_vectorizer()),
        ('clf',   MultinomialNB(alpha=0.1))
    ])
    nb_pipeline.fit(X_train, y_train)

    svm_pipeline = Pipeline([
        ('tfidf', build_vectorizer()),
        ('clf',   SVC(kernel='linear', probability=True, C=1.0, random_state=42))
    ])
    svm_pipeline.fit(X_train, y_train)

    # Evaluation report
    print("\n" + "═" * 46)
    print("   MODEL EVALUATION REPORT")
    print("═" * 46)
    for name, model in [("Naive Bayes", nb_pipeline), ("SVM (Linear)", svm_pipeline)]:
        preds = model.predict(X_test)
        acc   = accuracy_score(y_test, preds)
        print(f"\n  {name}  —  Accuracy: {acc * 100:.1f}%")
        print(classification_report(y_test, preds, zero_division=0))
    print("═" * 46 + "\n")

    return nb_pipeline, svm_pipeline


# ─────────────────────────────────────────────────────────
#  ENSEMBLE CLASSIFY
# ─────────────────────────────────────────────────────────

def classify_message(text, nb_model, svm_model):
    """
    Run both models on the text and combine results.
    Both agree  →  average confidence
    Disagree    →  SVM wins, confidence reduced to show uncertainty
    """
    cleaned = clean_text(text)

    nb_label = nb_model.predict([cleaned])[0]
    nb_conf  = round(max(nb_model.predict_proba([cleaned])[0]) * 100, 1)

    svm_label = svm_model.predict([cleaned])[0]
    svm_conf  = round(max(svm_model.predict_proba([cleaned])[0]) * 100, 1)

    if nb_label == svm_label:
        final_label = nb_label
        final_conf  = round((nb_conf + svm_conf) / 2, 1)
        agreement   = "✅ Both models agree"
    else:
        final_label = svm_label
        final_conf  = round(svm_conf * 0.72, 1)
        agreement   = "⚠️  Models disagree — SVM used as tiebreaker"

    return {
        'label':       final_label,
        'confidence':  final_conf,
        'agreement':   agreement,
        'naive_bayes': {'label': nb_label,  'confidence': nb_conf},
        'svm':         {'label': svm_label, 'confidence': svm_conf},
    }


# ─────────────────────────────────────────────────────────
#  DATASET HELPERS
# ─────────────────────────────────────────────────────────

def find_in_dataset(df, text):
    """Return the label if this exact message is already in the dataset."""
    match = df[df['message'].str.lower() == text.lower()]
    return match.iloc[0]['label'] if not match.empty else None


def save_to_dataset(df, text, label, csv_path):
    """Append a new row to the dataset and save."""
    new_row = pd.DataFrame({'message': [text], 'label': [label]})
    df      = pd.concat([df, new_row], ignore_index=True)
    df.to_csv(csv_path, index=False)
    return df


# ─────────────────────────────────────────────────────────
#  CHAT LOOP
# ─────────────────────────────────────────────────────────

def print_url_report(analyses):
    print("\n  🔗 URL THREAT ANALYSIS")
    print("  " + "─" * 44)
    for a in analyses:
        short = a['url'][:70] + ('…' if len(a['url']) > 70 else '')
        print(f"  URL    : {short}")
        print(f"  Score  : {a['score']}/100    Verdict: {a['verdict']}")
        for flag in a['flags']:
            print(f"           • {flag}")
        print()


def chat(df, nb_model, svm_model, csv_path):
    greetings = [
        "Hi! 👋 Paste any message or link to check it.",
        "Hello! Ready to detect spam.",
        "Hey there! Send me something to analyze."
    ]

    print("\n" + "═" * 50)
    print("  🛡️  SPAMSHIELD  ·  SVM + Naive Bayes + URL Scan")
    print("═" * 50)
    print("  Paste any message or URL to analyze.")
    print("  Type 'quit' to exit.\n")

    while True:
        try:
            user_input = input("You: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye! 👋")
            break

        if not user_input:
            continue

        if user_input.lower() in ('quit', 'exit', 'bye'):
            print("SpamShield: Goodbye! Stay safe online. 👋")
            break

        if user_input.lower() in ('hi', 'hello', 'hey'):
            print(f"SpamShield: {random.choice(greetings)}\n")
            continue

        print()

        # Step 1 — Scan any URLs found in the message
        urls = extract_urls(user_input)
        if urls:
            print_url_report([analyze_url(u) for u in urls])

        # Step 2 — Check if it's already in the dataset
        existing = find_in_dataset(df, user_input)
        if existing:
            print(f"  📂 Found in dataset — Label: {existing.upper()}\n")
            continue

        # Step 3 — Run the ML ensemble
        result = classify_message(user_input, nb_model, svm_model)

        print("  🤖 CLASSIFICATION RESULT")
        print("  {'─' * 34}")
        print("  Final Verdict  : {result['label'].upper()}")
        print("  Confidence     : {result['confidence']}%")
        print("  Naive Bayes    : {result['naive_bayes']['label'].upper()} "
              f"({result['naive_bayes']['confidence']}%)")
        print("  SVM            : {result['svm']['label'].upper()} "
              f"({result['svm']['confidence']}%)")
        print(f"  {result['agreement']}\n")

        # Step 4 — Collect feedback to improve the dataset over time
        feedback = input("  Is this correct? (y / n / skip): ").strip().lower()
        if feedback == 'skip':
            print()
        elif feedback == 'n':
            correction = input("  Correct label (spam / ham): ").strip().lower()
            if correction in ('spam', 'ham'):
                df = save_to_dataset(df, user_input, correction, csv_path)
                print("  ✅ Saved correction to dataset.\n")
            else:
                print("  Unrecognised label — skipping.\n")
        else:
            df = save_to_dataset(df, user_input, result['label'], csv_path)
            print("  ✅ Confirmed and saved.\n")




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SpamShield — spam & phishing detector')
    parser.add_argument(
        '--csv',
        default='dataset/Book2.csv',
        help='Path to your CSV dataset (needs "message" and "label" columns)'
    )
    args = parser.parse_args()

    print(f"\nLoading dataset: {args.csv}")
    try:
        df = pd.read_csv(args.csv)
    except FileNotFoundError:
        print(f"\n  ERROR: No file found at '{args.csv}'")
        print("  Put your CSV at  dataset/Book2.csv")
        print("  or run:  python spam_detector.py --csv your_file.csv\n")
        sys.exit(1)

    print(f"Loaded {len(df)} messages. Training models...\n")
    nb_model, svm_model = train_models(df)
    chat(df, nb_model, svm_model, args.csv)
