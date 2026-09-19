import React from 'react';
import { FileText, Download, X } from 'lucide-react';
import { api } from '../services/api';

export default function ForensicReportModal({ selectedCase, onClose }) {
  if (!selectedCase) return null;

  const pdfUrl = api.getReportPdfUrl(selectedCase.case_id);

  return (
    <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
      <div style={{ backgroundColor: '#131b2e', borderRadius: '8px', border: '1px solid #1e293b', width: '520px', maxWidth: '90%', padding: '20px', position: 'relative' }}>
        <button onClick={onClose} style={{ position: 'absolute', top: '16px', right: '16px', backgroundColor: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer' }}>
          <X size={18} />
        </button>

        <h3 style={{ margin: '0 0 8px 0', color: '#f8fafc', fontSize: '1.1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
          <FileText size={20} color="#3b82f6" /> Investigator-Ready Forensic Report
        </h3>

        <div style={{ fontSize: '0.78rem', color: '#94a3b8', marginBottom: '16px', lineHeight: '1.4' }}>
          Chain-of-Custody-Aware Forensic Evidence Export for Case <strong style={{ color: '#f8fafc' }}>{selectedCase.case_id}</strong>. Hashing and timestamp provenance support evidence integrity.
        </div>

        <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '14px', fontSize: '0.78rem', color: '#94a3b8', display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '20px' }}>
          <div><strong>Case ID:</strong> <span className="font-mono" style={{ color: '#3b82f6' }}>{selectedCase.case_id}</span></div>
          <div><strong>SHA-256 Hash:</strong> <span className="font-mono" style={{ color: '#94a3b8', fontSize: '0.7rem' }}>{selectedCase.message?.raw_hash}</span></div>
          <div><strong>Ingested Timestamp:</strong> {selectedCase.timestamps?.ingested_at}</div>
          <div><strong>Threat Verdict:</strong> <span style={{ color: selectedCase.detection?.verdict === 'HIGH_RISK' ? '#ef4444' : '#f59e0b', fontWeight: 700 }}>{selectedCase.detection?.verdict}</span></div>
          <div><strong>Evidence Objects Count:</strong> {selectedCase.evidence?.length || 0}</div>
        </div>

        <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={{ backgroundColor: '#0d1322', color: '#94a3b8', border: '1px solid #1e293b', borderRadius: '4px', padding: '8px 14px', fontSize: '0.78rem', cursor: 'pointer' }}>
            Close
          </button>
          <a
            href={pdfUrl}
            target="_blank"
            rel="noopener noreferrer"
            style={{ backgroundColor: '#3b82f6', color: '#fff', border: 'none', borderRadius: '4px', padding: '8px 14px', fontSize: '0.78rem', fontWeight: 600, textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
          >
            <Download size={14} /> Download Forensic PDF Report
          </a>
        </div>
      </div>
    </div>
  );
}
