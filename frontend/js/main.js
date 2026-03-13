// main.js — index page interactions
document.querySelectorAll('.feature-card').forEach((card, i) => {
  card.style.animationDelay = `${i * 0.08}s`;
});
