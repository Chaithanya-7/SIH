import React from 'react';
import { Globe, MapPin, AlertCircle, Info, Server, Network } from 'lucide-react';

export default function ThreatMap({ infrastructure }) {
  const origin = infrastructure?.origin || {};
  const geo = infrastructure?.geolocation || {};
  const anon = infrastructure?.anonymization || {};
  const dns = infrastructure?.dns || {};

  const originIp = origin.origin_ip || infrastructure?.origin_ip || null;
  const isGeoAvailable = geo.status === 'AVAILABLE' && geo.country;

  const country = isGeoAvailable ? geo.country : null;
  const city = isGeoAvailable ? geo.city : null;
  const region = isGeoAvailable ? geo.region : null;
  const isp = isGeoAvailable ? geo.isp : (infrastructure?.isp !== 'UNAVAILABLE' ? infrastructure?.isp : null);
  const asn = isGeoAvailable ? geo.asn : (infrastructure?.asn !== 'UNAVAILABLE' ? infrastructure?.asn : null);

  const hasAnonRisk = anon.status === 'AVAILABLE' && (anon.vpn || anon.proxy || anon.tor);

  return (
    <div style={{ backgroundColor: '#131b2e', borderRadius: '8px', border: '1px solid #1e293b', padding: '16px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
        <h4 style={{ margin: 0, fontSize: '0.9rem', color: '#f8fafc', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Globe size={16} color="#3b82f6" /> Probable Sending Infrastructure
        </h4>
        <div style={{ display: 'flex', gap: '8px' }}>
          {hasAnonRisk && (
            <span style={{ backgroundColor: 'rgba(239, 68, 68, 0.15)', color: '#ef4444', fontSize: '0.68rem', padding: '2px 6px', borderRadius: '4px', fontWeight: 600 }}>
              {anon.tor ? 'Tor Exit Node' : anon.vpn ? 'VPN Node' : 'Proxy Node'}
            </span>
          )}
          <span style={{ backgroundColor: isGeoAvailable ? 'rgba(16, 185, 129, 0.15)' : 'rgba(100, 116, 139, 0.15)', color: isGeoAvailable ? '#10b981' : '#94a3b8', fontSize: '0.68rem', fontWeight: 600, padding: '2px 6px', borderRadius: '4px' }}>
            Geo Status: {geo.status || 'UNAVAILABLE'}
          </span>
        </div>
      </div>

      {/* Mandatory Forensic Disclaimer Banner */}
      <div style={{ backgroundColor: '#0d1322', border: '1px solid #1e293b', borderRadius: '6px', padding: '8px 12px', fontSize: '0.72rem', color: '#94a3b8', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <AlertCircle size={15} style={{ flexShrink: 0, color: '#3b82f6' }} />
        <span>IP geolocation represents observed network infrastructure and does not establish the physical location or identity of the human sender.</span>
      </div>

      {/* Provider Limitation Note */}
      {origin.limitation && (
        <div style={{ backgroundColor: '#0d1322', border: '1px solid #1e293b', borderRadius: '6px', padding: '8px 12px', fontSize: '0.72rem', color: '#f59e0b', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Info size={15} style={{ flexShrink: 0, color: '#f59e0b' }} />
          <span><strong>Provider Limitation:</strong> {origin.limitation}</span>
        </div>
      )}

      {/* Infrastructure Card */}
      <div style={{ backgroundColor: '#0d1322', borderRadius: '6px', border: '1px solid #1e293b', padding: '14px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px', alignItems: 'center' }}>
        <div>
          <div style={{ fontSize: '0.72rem', color: '#64748b', marginBottom: '4px' }}>Probable Origin Candidate</div>
          {isGeoAvailable ? (
            <div style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
              <MapPin size={16} color="#ef4444" /> {city ? `${city}, ` : ''}{region ? `${region}, ` : ''}{country}
            </div>
          ) : (
            <div style={{ fontSize: '0.9rem', fontWeight: 600, color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
              <Server size={16} color="#94a3b8" /> Infrastructure geolocation unavailable
            </div>
          )}

          <div style={{ fontSize: '0.72rem', color: '#94a3b8', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div><strong>Origin IP:</strong> <span className="font-mono" style={{ color: '#f8fafc' }}>{originIp || 'UNAVAILABLE'}</span></div>
            <div><strong>Provider:</strong> {origin.origin_provider || 'External Mail Infrastructure'}</div>
            <div><strong>ASN / ISP:</strong> {asn || 'UNAVAILABLE'} / {isp || 'UNAVAILABLE'}</div>
            {dns.status === 'AVAILABLE' && <div><strong>Reverse DNS (PTR):</strong> <span className="font-mono" style={{ color: '#3b82f6' }}>{dns.ptr}</span></div>}
          </div>
        </div>

        {/* Visual Canvas Box */}
        <div style={{ backgroundColor: '#131b2e', borderRadius: '6px', height: '120px', border: '1px solid #1e293b', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '10px', textAlign: 'center' }}>
          {isGeoAvailable ? (
            <>
              <MapPin size={24} color="#ef4444" />
              <div style={{ fontSize: '0.75rem', color: '#f8fafc', fontWeight: 600, marginTop: '4px' }}>{city ? `${city}, ` : ''}{country}</div>
              <div className="font-mono" style={{ fontSize: '0.68rem', color: '#94a3b8' }}>{originIp}</div>
            </>
          ) : (
            <>
              <Network size={24} color="#64748b" />
              <div style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: 600, marginTop: '4px' }}>Infrastructure Geolocation Unavailable</div>
              <div className="font-mono" style={{ fontSize: '0.68rem', color: '#64748b' }}>{originIp || 'No routable IP'}</div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
