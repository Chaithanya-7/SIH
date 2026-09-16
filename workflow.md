┌─────────────────────────────┐
│       INCOMING EMAIL        │
└──────────────┬──────────────┘
               ↓
┌─────────────────────────────┐
│     MQL DETECTION LAYER     │
│   Initial Threat Detection  │
└──────────────┬──────────────┘
               ↓
       Suspicious Email
               ↓
┌─────────────────────────────┐
│       AI INTELLIGENCE       │
│                             │
│  DeBERTa / RoBERTa          │
│  • Phishing                 │
│  • BEC                      │
│  • Impersonation            │
│  • Intent                   │
└──────────────┬──────────────┘
               ↓
┌─────────────────────────────┐
│    BEHAVIORAL AI            │
│    Isolation Forest         │
│    Anomaly Detection        │
└──────────────┬──────────────┘
               ↓
┌─────────────────────────────┐
│      FORENSIC ENGINE        │
│ SPF • DKIM • DMARC • Relay  │
└──────────────┬──────────────┘
               ↓
┌─────────────────────────────┐
│     IOC + INFRASTRUCTURE    │
│ IP • URL • Domain • Geo     │
│ ASN • Reputation • DNS      │
└──────────────┬──────────────┘
               ↓
┌─────────────────────────────┐
│      CAMPAIGN GRAPH         │
│   Cross-Email Correlation   │
└──────────────┬──────────────┘
               ↓
┌─────────────────────────────┐
│      AI EVIDENCE FUSION     │
│       XGBoost + SHAP        │
└──────────────┬──────────────┘
               ↓
         THREAT SCORE
               ↓
┌─────────────────────────────┐
│    LLM INVESTIGATION AI     │
│ Explain • Summarize • Advise│
└──────────────┬──────────────┘
               ↓
        THREAT CASE
               ↓
   QUARANTINE / ADMIN REVIEW
               ↓
       FORENSIC REPORT
