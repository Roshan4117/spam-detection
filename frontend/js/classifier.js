// ── Classifier Module ───────────────────────────────────────
// classifier.js — Simulated SVM + Naïve Bayes ensemble

const Classifier = (() => {
  // Feature weights (approximating trained TF-IDF model)
  const FEATURES = {
    strong_spam: [
      'win','winner','prize','lottery','free','claim','urgent','act now','limited time',
      'click here','verify your account','suspicious activity','congratulations','selected',
      'reward','cash','million','inheritance','nigerian','prince','bank account','password',
      'credit card','ssn','social security','unsubscribe','dear friend','you have been chosen',
      'account suspended','account blocked','confirm identity','validate','100% free',
      'risk free','guarantee','no obligation','special promotion','exclusive offer'
    ],
    moderate_spam: [
      'offer','deal','discount','save','buy','order','subscribe','bonus','exclusive',
      'promo','promotion','sale','cheap','lowest price','best price','save money',
      'earn money','make money','work from home','extra income','click below'
    ],
    mild_spam: ['click','link','visit','check','sale','http'],
    ham_signals: [
      'meeting','schedule','project','update','team','report','please','attached',
      'regarding','following up','thanks','let me know','hi','hello','good morning',
      'dear','best regards','sincerely','as discussed','per our conversation',
      'i hope','looking forward','please find','kind regards','best wishes'
    ]
  };

  function tokenize(text) { return text.toLowerCase().split(/\s+/); }

  function naiveBayes(text) {
    const lower = text.toLowerCase();
    let score = 0;
    FEATURES.strong_spam.forEach(f => { if (lower.includes(f)) score += 3.0; });
    FEATURES.moderate_spam.forEach(f => { if (lower.includes(f)) score += 1.5; });
    FEATURES.mild_spam.forEach(f => { if (lower.includes(f)) score += 0.7; });
    FEATURES.ham_signals.forEach(f => { if (lower.includes(f)) score -= 1.5; });
    score += (text.match(/!/g) || []).length * 0.5;
    score += (text.match(/\b[A-Z]{2,}\b/g) || []).length * 0.4;
    score += (URLScanner.extractURLs(text).length) * 0.6;

    const norm = Math.max(0, Math.min(score, 18)) / 18;
    const label = norm >= 0.38 ? 'spam' : 'ham';
    const conf  = Math.round((label === 'spam' ? norm : 1 - norm) * 100);
    return { label, confidence: conf };
  }

  function svm(text) {
    // SVM uses different weight distribution — stronger penalty for ham signals
    const lower = text.toLowerCase();
    let score = 0;
    FEATURES.strong_spam.forEach(f => { if (lower.includes(f)) score += 2.8; });
    FEATURES.moderate_spam.forEach(f => { if (lower.includes(f)) score += 1.2; });
    FEATURES.mild_spam.forEach(f => { if (lower.includes(f)) score += 0.5; });
    FEATURES.ham_signals.forEach(f => { if (lower.includes(f)) score -= 2.2; }); // SVM penalizes ham signals harder
    score += (text.match(/!/g) || []).length * 0.65;
    score += (text.match(/\b[A-Z]{2,}\b/g) || []).length * 0.55;
    score += (URLScanner.extractURLs(text).length) * 0.9; // SVM weights URLs more

    const norm = Math.max(0, Math.min(score, 16)) / 16;
    const label = norm >= 0.36 ? 'spam' : 'ham'; // SVM decision boundary
    const conf  = Math.round((label === 'spam' ? norm : 1 - norm) * 100);
    return { label, confidence: conf };
  }

  function classify(text) {
    const nb  = naiveBayes(text);
    const sv  = svm(text);
    let finalLabel, finalConf, agreement;

    if (nb.label === sv.label) {
      finalLabel = nb.label;
      finalConf  = Math.round((nb.confidence + sv.confidence) / 2);
      agreement  = { text: '✅ Both models agree', type: 'agree' };
    } else {
      finalLabel = sv.label; // SVM wins tiebreak
      finalConf  = Math.round(sv.confidence * 0.72);
      agreement  = { text: '⚠️ Models disagree — SVM used as tiebreaker', type: 'disagree' };
    }

    return { label: finalLabel, confidence: finalConf, nb, svm: sv, agreement };
  }

  return { classify };
})();
