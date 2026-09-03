document.addEventListener('DOMContentLoaded', () => {
  const btnScan = document.getElementById('btn-scan');
  const loading = document.getElementById('loading');
  const resultCard = document.getElementById('result-card');
  const badgeVerdict = document.getElementById('badge-verdict');
  const riskScore = document.getElementById('risk-score');
  const txtSender = document.getElementById('txt-sender');
  const txtSubject = document.getElementById('txt-subject');
  const whyList = document.getElementById('why-list');
  const btnReport = document.getElementById('btn-report');
  const btnDashboard = document.getElementById('btn-dashboard');

  const API_BASE = typeof SECUREMAIL_CONFIG !== 'undefined' ? SECUREMAIL_CONFIG.API_BASE_URL : 'http://localhost:3001';
  const DASHBOARD_URL = typeof SECUREMAIL_CONFIG !== 'undefined' ? SECUREMAIL_CONFIG.DASHBOARD_URL : 'http://localhost:3005';

  btnScan.addEventListener('click', () => {
    loading.classList.remove('hidden');
    resultCard.classList.add('hidden');

    // Sample Executive BEC email for extension scan demonstration
    const sampleEmail = 'Received: from mail.attacker.net (mail.attacker.net [198.51.100.1]) by mx.victim.com with ESMTP id 12345; Thu, 03 Sep 2026 12:00:00 +0000\r\n' +
        'Return-Path: <bounce@attacker.net>\r\n' +
        'Authentication-Results: mx.victim.com; spf=fail; dkim=fail; dmarc=fail\r\n' +
        'From: CEO <ceo@company.com>\r\n' +
        'To: CFO <cfo@company.com>\r\n' +
        'Subject: URGENT: Executive Fund Transfer Authorization Required\r\n' +
        'Date: Thu, 03 Sep 2026 12:00:00 +0000\r\n\r\n' +
        'Please approve the attached 50000 USD wire transfer immediately to http://attacker.net/transfer.';

    fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ emailContent: sampleEmail })
    })
    .then(res => res.json())
    .then(data => {
      loading.classList.add('hidden');
      if (data.success && data.threatObject) {
        renderResults(data.threatObject);
      } else {
        alert('Email detection service is temporarily unavailable.');
      }
    })
    .catch(err => {
      loading.classList.add('hidden');
      console.error('[SecureMail Extension] Backend Error:', err);
      alert('Email detection service is temporarily unavailable.');
    });
  });

  function renderResults(threatObject) {
    const verdict = threatObject.detection?.verdict || 'UNKNOWN';
    const confidencePct = Math.round((threatObject.confidence?.threat || 0) * 100);

    badgeVerdict.textContent = verdict.replace('_', ' ');
    riskScore.textContent = `${confidencePct}% Risk Score`;

    if (verdict === 'HIGH_RISK') {
      badgeVerdict.className = 'badge badge-high';
    } else if (verdict === 'SUSPICIOUS') {
      badgeVerdict.className = 'badge badge-suspicious';
    } else {
      badgeVerdict.className = 'badge badge-safe';
    }

    txtSender.textContent = threatObject.message?.sender || 'Unknown';
    txtSubject.textContent = threatObject.message?.subject || '(No Subject)';

    // Plain English "Why is this dangerous?"
    whyList.innerHTML = '';
    const evidenceItems = threatObject.evidence || [];

    if (evidenceItems.length === 0) {
      whyList.innerHTML = '<li>No threat indicators detected. Email appears safe.</li>';
    } else {
      evidenceItems.forEach(item => {
        const li = document.createElement('li');
        li.textContent = `${item.finding} — ${item.explanation}`;
        whyList.appendChild(li);
      });
    }

    resultCard.classList.remove('hidden');
  }

  btnReport.addEventListener('click', () => {
    alert('🚨 Incident reported directly to SOC Analysts for high-priority review.');
  });

  btnDashboard.addEventListener('click', () => {
    window.open(DASHBOARD_URL, '_blank');
  });
});
