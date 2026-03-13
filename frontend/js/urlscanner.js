// ── URL Scanner Module ──────────────────────────────────────
// urlscanner.js — 10-factor URL threat analysis

const URLScanner = (() => {
  const SUSPICIOUS_TLDS = ['.xyz','.tk','.ml','.ga','.cf','.gq','.pw','.top','.click','.link','.download','.zip','.mov'];
  const PHISHING_KW = ['login','verify','account','update','secure','bank','paypal','free','win','prize','click','urgent','confirm','suspend','ebay','amazon','apple','google','microsoft'];
  const SHORTENERS  = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','rb.gy','cutt.ly'];
  const TRUSTED     = new Set(['google.com','youtube.com','facebook.com','twitter.com','instagram.com','amazon.com','microsoft.com','apple.com','github.com','linkedin.com','wikipedia.org','reddit.com','netflix.com','stackoverflow.com','gmail.com','outlook.com']);
  const TYPO_MAP    = { 'g00gle':'google','paypa1':'paypal','amaz0n':'amazon','faceb00k':'facebook','micros0ft':'microsoft','app1e':'apple','go0gle':'google','paypa1':'paypal' };

  function extractURLs(text) {
    const re = /(https?:\/\/[^\s<>"{}|\\^`\[\]]+|www\.[a-zA-Z0-9][^\s<>"{}|\\^`\[\]]*)/gi;
    return [...new Set(text.match(re) || [])];
  }

  function analyze(rawUrl) {
    const res = { url: rawUrl, score: 0, flags: [], verdict: 'UNKNOWN', cls: 'unknown' };
    try {
      const url = rawUrl.startsWith('http') ? rawUrl : 'http://' + rawUrl;
      const p = new URL(url);
      const domain = p.hostname.replace(/^www\./, '').toLowerCase();
      const lower  = url.toLowerCase();
      const baseDomain = domain.split('.').slice(-2).join('.');

      // Trusted domain → early low score
      if (TRUSTED.has(baseDomain)) {
        res.score = Math.max(0, res.score - 40);
        res.flags.push({ text: `✓ Trusted domain: ${baseDomain}`, good: true });
      }

      // HTTP only
      if (p.protocol === 'http:') { res.score += 15; res.flags.push({ text: 'No HTTPS — unencrypted connection' }); }

      // IP address
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) { res.score += 35; res.flags.push({ text: 'IP address used instead of hostname' }); }

      // Suspicious TLD
      const badTld = SUSPICIOUS_TLDS.find(t => domain.endsWith(t));
      if (badTld) { res.score += 25; res.flags.push({ text: `Suspicious TLD: ${badTld}` }); }

      // Phishing keywords
      const kwHits = PHISHING_KW.filter(k => lower.includes(k));
      if (kwHits.length) { res.score += Math.min(kwHits.length * 10, 30); res.flags.push({ text: `Phishing keywords: ${kwHits.slice(0,3).join(', ')}${kwHits.length > 3 ? '…' : ''}` }); }

      // Excessive subdomains
      const levels = domain.split('.').length - 1;
      if (levels > 3) { res.score += 20; res.flags.push({ text: `Excessive subdomains (${levels} levels)` }); }

      // Long URL
      if (rawUrl.length > 100) { res.score += 10; res.flags.push({ text: `Very long URL (${rawUrl.length} chars)` }); }

      // URL shortener
      if (SHORTENERS.some(s => domain === s || domain.endsWith('.' + s))) { res.score += 20; res.flags.push({ text: 'URL shortener — real destination hidden' }); }

      // @ trick
      if (rawUrl.includes('@')) { res.score += 30; res.flags.push({ text: '@ in URL — deceptive redirect technique' }); }

      // Typosquatting
      for (const [fake, real] of Object.entries(TYPO_MAP)) {
        if (domain.includes(fake)) { res.score += 40; res.flags.push({ text: `Possible typosquatting of ${real}` }); break; }
      }

      res.score = Math.min(100, Math.max(0, res.score));

      if      (res.score >= 60) { res.verdict = 'SUSPICIOUS';    res.cls = 'suspicious'; }
      else if (res.score >= 30) { res.verdict = 'POTENTIALLY RISKY'; res.cls = 'risky'; }
      else                      { res.verdict = 'LIKELY SAFE';   res.cls = 'safe'; }

    } catch (e) {
      res.flags.push({ text: 'Could not parse URL' });
      res.verdict = 'UNKNOWN'; res.cls = 'unknown';
    }
    return res;
  }

  function verdictIcon(cls) {
    return { suspicious: '🔴', risky: '🟡', safe: '🟢', unknown: '⚪' }[cls] || '⚪';
  }

  return { extractURLs, analyze, verdictIcon };
})();
