import { fetch } from '@/lib/api/http';

interface CisaVulnerability {
    cveID: string;
    vulnerabilityName: string;
    vendorProject: string;
    product: string;
    dateAdded: string;
    dueDate: string;
}

interface CisaResponse {
    vulnerabilities?: CisaVulnerability[];
}

export interface CyberThreat {
    id: string;
    name: string;
    vendor: string;
    product: string;
    severity: 'CRITICAL';
    date: string;
    due: string;
    source: string;
}

type ThreatLevel = 'CRITICAL' | 'HIGH' | 'ELEVATED';

function threatLevelFor(count: number): ThreatLevel {
    if (count >= 8) return 'CRITICAL';
    if (count >= 4) return 'HIGH';
    return 'ELEVATED';
}

export interface CyberThreatsResult {
    threats: CyberThreat[];
    stats: {
        cisa_total?: number;
        shadowserver?: 'active' | 'unavailable';
        active_cves?: number;
        threat_level?: ThreatLevel;
    };
    timestamp: string;
    error?: string;
}

export async function fetchCyberThreats(): Promise<CyberThreatsResult> {
    try {
        const results: CyberThreatsResult = { threats: [], stats: {}, timestamp: new Date().toISOString() };

        // 1. CISA Known Exploited Vulnerabilities
        try {
            const res = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
            if (res.ok) {
                const data: CisaResponse = await res.json();
                const recent: CyberThreat[] = (data.vulnerabilities || [])
                    .filter((v) => {
                        const added = new Date(v.dateAdded);
                        const daysAgo = (Date.now() - added.getTime()) / (1000 * 60 * 60 * 24);
                        return daysAgo <= 30;
                    })
                    .slice(0, 10)
                    .map((v) => ({
                        id: v.cveID,
                        name: v.vulnerabilityName,
                        vendor: v.vendorProject,
                        product: v.product,
                        severity: 'CRITICAL',
                        date: v.dateAdded,
                        due: v.dueDate,
                        source: 'CISA KEV',
                    }));
                results.threats.push(...recent);
                results.stats.cisa_total = data.vulnerabilities?.length || 0;
            }
        } catch (e) { console.warn('[OSIRIS] Suppressed error:', e instanceof Error ? e.message : e); }

        // 2. Shadowserver honeypot stats
        try {
            const res = await fetch('https://dashboard.shadowserver.org/statistics/combined/map/', {
                headers: { 'Accept': 'application/json' },
            });
            if (res.ok) {
                results.stats.shadowserver = 'active';
            }
        } catch {
            results.stats.shadowserver = 'unavailable';
        }

        // 3. Aggregate stats
        results.stats.active_cves = results.threats.length;
        results.stats.threat_level = threatLevelFor(results.threats.length);

        return results;
    } catch {
        return { threats: [], stats: {}, timestamp: new Date().toISOString(), error: 'Failed' };
    }
}