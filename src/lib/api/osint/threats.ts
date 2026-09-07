import { fetch } from '@/lib/api/http';

interface OtxPulse {
    name: string;
    description?: string;
    created: string;
    modified: string;
    tags?: string[];
    adversary?: string;
    targeted_countries?: string[];
    indicator_count?: number;
}

interface OtxPulseFeedResponse {
    results?: OtxPulse[];
}

interface OtxIpResponse {
    reputation?: number;
    pulse_info?: { count?: number };
    country_name?: string;
    asn?: string;
}

interface OtxDomainWhois {
    registrar?: string;
    creation_date?: string;
    expiration_date?: string;
}

interface OtxDomainResponse {
    pulse_info?: { count?: number };
    whois?: OtxDomainWhois;
}

export interface ThreatPulse {
    name: string;
    description?: string;
    created: string;
    modified: string;
    tags?: string[];
    adversary?: string;
    targeted_countries?: string[];
    indicators_count?: number;
}

export interface ThreatOtxInfo {
    reputation?: number;
    pulse_count: number;
    country?: string;
    asn?: string;
    whois?: {
        registrar?: string;
        creation_date?: string;
        expiration_date?: string;
    } | null;
}

export interface ThreatsResult {
    timestamp: string;
    pulses?: ThreatPulse[];
    tor_exit_node?: boolean | null;
    otx?: ThreatOtxInfo;
    threat_level: 'HIGH' | 'MEDIUM' | 'LOW';
    error?: string;
}

function threatLevelFor(pulseCount: number): 'HIGH' | 'MEDIUM' | 'LOW' {
    if (pulseCount > 5) return 'HIGH';
    if (pulseCount > 0) return 'MEDIUM';
    return 'LOW';
}

export async function fetchThreats(query?: string): Promise<ThreatsResult> {
    try {
        const results: ThreatsResult = { timestamp: new Date().toISOString(), threat_level: 'LOW' };

        try {
            const res = await fetch('https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10&page=1', {
                signal: AbortSignal.timeout(8000),
                headers: { 'Accept': 'application/json' },
            });
            if (!res.ok) {
                const actRes = await fetch('https://otx.alienvault.com/api/v1/pulses/activity?limit=10', {
                    signal: AbortSignal.timeout(8000),
                });
                if (actRes.ok) {
                    const data: OtxPulseFeedResponse = await actRes.json();
                    results.pulses = (data.results || []).slice(0, 10).map((p) => ({
                        name: p.name,
                        description: p.description?.slice(0, 200),
                        created: p.created,
                        modified: p.modified,
                        tags: p.tags?.slice(0, 5),
                        adversary: p.adversary,
                        targeted_countries: p.targeted_countries,
                        indicators_count: p.indicator_count,
                    }));
                }
            }
        } catch (e) { console.warn('[OSIRIS] Suppressed error:', e instanceof Error ? e.message : e); }

        if (query) {
            const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(query);

            if (isIP) {
                try {
                    const torRes = await fetch('https://check.torproject.org/torbulkexitlist', {
                        signal: AbortSignal.timeout(5000),
                    });
                    if (torRes.ok) {
                        const torList = await torRes.text();
                        results.tor_exit_node = torList.includes(query);
                    }
                } catch {
                    results.tor_exit_node = null;
                }

                try {
                    const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/IPv4/${query}/general`, {
                        signal: AbortSignal.timeout(5000),
                    });
                    if (res.ok) {
                        const data: OtxIpResponse = await res.json();
                        results.otx = {
                            reputation: data.reputation,
                            pulse_count: data.pulse_info?.count || 0,
                            country: data.country_name,
                            asn: data.asn,
                        };
                    }
                } catch (e) { console.warn('[OSIRIS] Suppressed error:', e instanceof Error ? e.message : e); }
            } else {
                try {
                    const res = await fetch(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(query)}/general`, {
                        signal: AbortSignal.timeout(5000),
                    });
                    if (res.ok) {
                        const data: OtxDomainResponse = await res.json();
                        results.otx = {
                            pulse_count: data.pulse_info?.count || 0,
                            whois: data.whois ? {
                                registrar: data.whois.registrar,
                                creation_date: data.whois.creation_date,
                                expiration_date: data.whois.expiration_date,
                            } : null,
                        };
                    }
                } catch (e) { console.warn('[OSIRIS] Suppressed error:', e instanceof Error ? e.message : e); }
            }
        }

        results.threat_level = threatLevelFor(results.otx?.pulse_count || 0);

        return results;
    } catch {
        return { timestamp: new Date().toISOString(), threat_level: 'LOW', error: 'Threat lookup failed' };
    }
}