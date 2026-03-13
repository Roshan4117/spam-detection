// ── Chatbot UI Controller ───────────────────────────────────
// chatbot.js — calls Flask /analyze API instead of local classifier

const chatbox  = document.getElementById('chatbox');
const textarea = document.getElementById('chat-textarea');
const sendBtn  = document.getElementById('send-btn');

// Auto-resize textarea
textarea.addEventListener('input', () => {
  textarea.style.height = 'auto';
  textarea.style.height = Math.min(textarea.scrollHeight, 100) + 'px';
});

// Send on Enter (Shift+Enter = newline)
textarea.addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend(); }
});
sendBtn.addEventListener('click', handleSend);

// ── Main send handler ─────────────────────────────────────
async function handleSend() {
  const text = textarea.value.trim();
  if (!text) return;
  textarea.value = '';
  textarea.style.height = 'auto';

  appendMessage(text, 'outgoing');
  const thinkingLi = appendThinking();
  chatbox.scrollTo(0, chatbox.scrollHeight);

  // Simple greeting — no need to call the API
  if (['hi', 'hello', 'hey', 'sup'].includes(text.toLowerCase())) {
    chatbox.removeChild(thinkingLi);
    appendMessage("Hi! 👋 Paste any message or URL and I'll analyze it for spam and phishing threats.", 'incoming');
    chatbox.scrollTo(0, chatbox.scrollHeight);
    return;
  }

  // Call the Flask backend
  try {
    const response = await fetch('/analyze', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ message: text })
    });

    if (!response.ok) throw new Error('Server error');

    const data = await response.json();
    chatbox.removeChild(thinkingLi);
    appendHTML(buildResult(data, text));

  } catch (err) {
    chatbox.removeChild(thinkingLi);
    appendMessage('⚠️ Could not reach the server. Make sure Flask is running with: python backend/app.py', 'incoming');
  }

  chatbox.scrollTo(0, chatbox.scrollHeight);
}

// ── Build result card from API response ──────────────────
function buildResult(data, originalText) {
  const cls      = data.classification;
  const urlScans = data.urls || [];
  const isSpam   = cls.label === 'spam';

  let html = `<div class="result-card">
    <div class="rc-verdict ${isSpam ? 'spam' : 'ham'}">
      <div class="rv-icon">${isSpam ? '🚨' : '✅'}</div>
      <div>
        <div class="rv-label ${isSpam ? 'spam' : 'ham'}">${cls.label.toUpperCase()}</div>
        <div class="rv-conf">Ensemble Confidence: ${cls.confidence}%</div>
      </div>
    </div>

    <div class="rc-models">
      <div class="rc-model">
        <div class="rcm-name">🧠 NAIVE BAYES</div>
        <div class="rcm-pred ${cls.naive_bayes.label}">${cls.naive_bayes.label.toUpperCase()}</div>
        <div class="rcm-conf">${cls.naive_bayes.confidence}% confident</div>
      </div>
      <div class="rc-model">
        <div class="rcm-name">⚡ SVM</div>
        <div class="rcm-pred ${cls.svm.label}">${cls.svm.label.toUpperCase()}</div>
        <div class="rcm-conf">${cls.svm.confidence}% confident</div>
      </div>
    </div>

    <div class="rc-agreement">${cls.agree_type === 'agree' ? '✅' : '⚠️'} ${cls.agreement}</div>`;

  // URL cards
  if (urlScans.length > 0) {
    html += `<div class="rc-urls"><div class="rc-urls-title">🔗 URL THREAT ANALYSIS (${urlScans.length} found)</div>`;
    urlScans.forEach(s => {
      const shortUrl = s.url.length > 48 ? s.url.slice(0, 48) + '…' : s.url;
      const flagItems = s.flags.map(f => `<li>${f}</li>`).join('');
      html += `<div class="url-card ${s.cls}">
        <div class="uc-host">${shortUrl}</div>
        <div class="uc-verdict">${verdictIcon(s.cls)} ${s.verdict}</div>
        <div class="uc-score">Risk Score: ${s.score}/100</div>
        ${s.flags.length ? `<ul class="uc-flags">${flagItems}</ul>` : ''}
      </div>`;
    });
    html += `</div>`;
  }

  // Feedback buttons
  html += `<div class="rc-feedback">
    <span class="fb-label">Was this correct?</span>
    <button class="fb-btn fb-yes" onclick="sendFeedback(this, '${escAttr(originalText)}', '${cls.label}')">✅ Yes</button>
    <button class="fb-btn fb-spam" onclick="sendFeedback(this, '${escAttr(originalText)}', 'spam')">🚨 It's Spam</button>
    <button class="fb-btn fb-ham"  onclick="sendFeedback(this, '${escAttr(originalText)}', 'ham')">✅ It's Ham</button>
  </div>`;

  html += `</div>`;
  return html;
}

// ── Feedback ──────────────────────────────────────────────
async function sendFeedback(btn, message, label) {
  // Disable all buttons in this card
  btn.closest('.rc-feedback').querySelectorAll('button').forEach(b => b.disabled = true);
  btn.textContent = 'Saving…';

  try {
    await fetch('/feedback', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ message, label })
    });
    btn.closest('.rc-feedback').innerHTML = '<span class="fb-label">✅ Feedback saved — thanks!</span>';
  } catch {
    btn.closest('.rc-feedback').innerHTML = '<span class="fb-label">⚠️ Could not save feedback.</span>';
  }
}

// ── UI helpers ────────────────────────────────────────────
function verdictIcon(cls) {
  return { suspicious: '🔴', risky: '🟡', safe: '🟢', unknown: '⚪' }[cls] || '⚪';
}

function appendMessage(text, type) {
  const li = document.createElement('li');
  li.className = `chat ${type}`;
  li.innerHTML = type === 'incoming'
    ? `<div class="chat-avatar">🛡️</div><p>${escHtml(text)}</p>`
    : `<p>${escHtml(text)}</p>`;
  chatbox.appendChild(li);
  return li;
}

function appendHTML(html) {
  const li = document.createElement('li');
  li.className = 'chat incoming';
  li.innerHTML = `<div class="chat-avatar">🛡️</div>${html}`;
  chatbox.appendChild(li);
  return li;
}

function appendThinking() {
  const li = document.createElement('li');
  li.className = 'chat incoming';
  li.innerHTML = `<div class="chat-avatar">🛡️</div><p><div class="thinking"><span></span><span></span><span></span></div></p>`;
  chatbox.appendChild(li);
  return li;
}

function escHtml(str) {
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function escAttr(str) {
  return str.replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/"/g,'&quot;').replace(/\n/g,' ');
}
