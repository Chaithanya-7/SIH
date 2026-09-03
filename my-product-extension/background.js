// SecureMail AI Extension Background Service Worker
importScripts('config.js');

chrome.runtime.onInstalled.addListener(() => {
  console.log('[SecureMail Extension] Extension installed and background service worker active.');
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'ANALYZE_EMAIL') {
    const apiBase = typeof SECUREMAIL_CONFIG !== 'undefined' ? SECUREMAIL_CONFIG.API_BASE_URL : 'http://localhost:3001';
    fetch(`${apiBase}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ emailContent: request.emailContent })
    })
    .then(res => res.json())
    .then(data => sendResponse({ success: true, data }))
    .catch(err => {
      console.error('[SecureMail Extension Background] Fetch Error:', err);
      sendResponse({ success: false, error: 'Email detection service is temporarily unavailable.' });
    });
    return true; // Keep channel open for async response
  }
});
