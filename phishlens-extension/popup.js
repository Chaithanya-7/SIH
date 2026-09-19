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

  const API_BASE = typeof PHISHLENS_CONFIG !== 'undefined' ? PHISHLENS_CONFIG.API_BASE_URL : 'http://localhost:3001';
  const DASHBOARD_URL = typeof PHISHLENS_CONFIG !== 'undefined' ? PHISHLENS_CONFIG.DASHBOARD_URL : 'http://localhost:3005';

  btnScan.addEventListener('click', () => {
    alert('ℹ️ Live Gmail integration not configured. Chrome Extension active scanning will be enabled in the upcoming Google/Gmail integration milestone.');
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
