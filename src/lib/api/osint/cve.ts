import { fetch } from '@/lib/api/http';

interface CvssMetric {
    baseScore?: number;
    vectorString?: string;
    baseSeverity?: string;
}

interface CveMetric {
    cvssV3_1?: CvssMetric;
    cvssV3_0?: CvssMetric;
    cvssV31?: CvssMetric;
    cvssV2_0?: CvssMetric;
    cvssV2?: CvssMetric;
}

interface CveDescription {
    lang: string;
    value: string;
}

interface CveReference {
    url: string;
}

interface CveAffectedVersion {
    version?: string;
}

interface CveAffected {
    vendor?: string;
    product?: string;
    versions?: CveAffectedVersion[];
}

interface CveProblemTypeDescription {
    cweId?: string;
    description?: string;
}

interface CveContainerCna {
    descriptions?: CveDescription[];
    metrics?: CveMetric[];
    problemTypes?: { descriptions?: CveProblemTypeDescription[] }[];
    references?: CveReference[];
    affected?: CveAffected[];
}

interface MitreCveResponse {
    containers?: { cna?: CveContainerCna };
    cveMetadata?: {
        cveId?: string;
        datePublished?: string;
        dateUpdated?: string;
    };
}

interface CirclCveResponse {
    id?: string;
    summary?: string;
    cvss?: number;
    cvss_vector?: string;
    references?: string[];
    Published?: string;
    Modified?: string;
    cwe?: string;
}

export interface CveAffectedProduct {
    vendor: string;
    product: string;
    versions: string[];
}

export interface CveResult {
    id: string;
    description: string;
    cvss: number | null;
    cvss_vector?: string | null;
    severity?: string | null;
    cwe?: string | null;
    affected?: CveAffectedProduct[];
    references: string[];
    published?: string | null;
    modified?: string | null;
    source: 'mitre' | 'circl' | 'unavailable';
    error?: string;
}

function severityFor(cvss: number | null): string | null {
    if (cvss === null) return null;
    if (cvss >= 9) return 'CRITICAL';
    if (cvss >= 7) return 'HIGH';
    if (cvss >= 4) return 'MEDIUM';
    return 'LOW';
}

export async function fetchCve(cve: string): Promise<CveResult> {
    if (!cve) {
        return { id: '', description: '', cvss: null, references: [], source: 'unavailable', error: 'Missing cve parameter' };
    }

    if (!/^CVE-\d{4}-\d{4,}$/i.test(cve)) {
        return { id: cve, description: '', cvss: null, references: [], source: 'unavailable', error: 'Invalid CVE format. Expected: CVE-YYYY-NNNNN' };
    }

    try {
        const res = await fetch(`https://cveawg.mitre.org/api/cve/${encodeURIComponent(cve.toUpperCase())}`, {
            signal: AbortSignal.timeout(8000),
            headers: { 'Accept': 'application/json' },
        });

        if (!res.ok) {
            try {
                const circlRes = await fetch(`https://cve.circl.lu/api/cve/${encodeURIComponent(cve.toUpperCase())}`, {
                    signal: AbortSignal.timeout(8000),
                    headers: { 'Accept': 'application/json' },
                });
                if (circlRes.ok) {
                    const data: CirclCveResponse = await circlRes.json();
                    return {
                        id: data.id || cve.toUpperCase(),
                        description: data.summary || 'No description available.',
                        cvss: data.cvss ?? null,
                        cvss_vector: data.cvss_vector || null,
                        references: (data.references || []).slice(0, 5),
                        published: data.Published || null,
                        modified: data.Modified || null,
                        cwe: data.cwe || null,
                        source: 'circl',
                    };
                }
            } catch { /* fall through */ }

            return {
                id: cve.toUpperCase(),
                description: 'CVE details could not be retrieved at this time.',
                cvss: null,
                references: [],
                source: 'unavailable',
            };
        }

        const data: MitreCveResponse = await res.json();

        const cna = data.containers?.cna;
        const description = cna?.descriptions?.find((d) => d.lang === 'en')?.value
            || cna?.descriptions?.[0]?.value
            || 'No description available.';

        let cvss: number | null = null;
        let cvss_vector: string | null = null;
        let severity: string | null = null;

        const metrics = cna?.metrics;
        if (metrics) {
            for (const m of metrics) {
                const v31 = m.cvssV3_1 || m.cvssV3_0 || m.cvssV31;
                if (v31) {
                    cvss = v31.baseScore ?? null;
                    cvss_vector = v31.vectorString ?? null;
                    severity = v31.baseSeverity ?? null;
                    break;
                }
                const v2 = m.cvssV2_0 || m.cvssV2;
                if (v2) {
                    cvss = v2.baseScore ?? null;
                    cvss_vector = v2.vectorString ?? null;
                    break;
                }
            }
        }

        const problemTypes = cna?.problemTypes;
        let cwe: string | null = null;
        if (problemTypes?.[0]?.descriptions?.[0]) {
            cwe = problemTypes[0].descriptions[0].cweId || problemTypes[0].descriptions[0].description || null;
        }

        const references = (cna?.references || []).slice(0, 5).map((r) => r.url);

        const affected: CveAffectedProduct[] = (cna?.affected || []).slice(0, 5).map((a) => ({
            vendor: a.vendor || 'Unknown',
            product: a.product || 'Unknown',
            versions: (a.versions || []).slice(0, 3).map((v) => v.version).filter((v): v is string => Boolean(v)),
        }));

        return {
            id: data.cveMetadata?.cveId || cve.toUpperCase(),
            description,
            cvss,
            cvss_vector,
            severity: severity || severityFor(cvss),
            cwe,
            affected,
            references,
            published: data.cveMetadata?.datePublished || null,
            modified: data.cveMetadata?.dateUpdated || null,
            source: 'mitre',
        };
    } catch {
        return { id: cve, description: '', cvss: null, references: [], source: 'unavailable', error: 'CVE lookup failed' };
    }
}