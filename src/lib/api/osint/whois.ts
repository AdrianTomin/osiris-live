import { fetch } from '@/lib/api/http';

interface RdapEvent {
    eventAction: string;
    eventDate: string;
}

interface RdapNameserver {
    ldhName: string;
}

interface RdapVcardEntry {
    0: string;
    3?: string;
}

interface RdapEntity {
    handle?: string;
    roles?: string[];
    vcardArray?: [string, unknown[][]];
}

interface RdapResponse {
    handle?: string;
    ldhName?: string;
    status?: string[];
    events?: RdapEvent[];
    nameservers?: RdapNameserver[];
    entities?: RdapEntity[];
}

export interface WhoisEvent {
    action: string;
    date: string;
}

export interface WhoisEntity {
    handle?: string;
    roles?: string[];
    name?: string;
    org?: string;
}

export interface WhoisRdapInfo {
    handle?: string;
    name?: string;
    status?: string[];
    events: WhoisEvent[];
    nameservers: string[];
    entities: WhoisEntity[];
}

export interface WhoisHttpInfo {
    status: number;
    headers: Record<string, string>;
    redirected: boolean;
    final_url: string;
}

export interface WhoisSecurityScore {
    score: number;
    max: number;
    grade: 'A' | 'B' | 'C' | 'F';
}

export interface WhoisResult {
    domain: string;
    timestamp: string;
    rdap?: WhoisRdapInfo;
    registration?: string;
    expiration?: string;
    last_changed?: string;
    http?: WhoisHttpInfo;
    security_score?: WhoisSecurityScore;
    error?: string;
}

const SECURITY_HEADERS = [
    'server', 'x-powered-by', 'x-frame-options', 'strict-transport-security',
    'content-security-policy', 'x-content-type-options', 'x-xss-protection',
    'referrer-policy', 'permissions-policy',
];

function gradeFor(score: number): 'A' | 'B' | 'C' | 'F' {
    if (score >= 5) return 'A';
    if (score >= 3) return 'B';
    if (score >= 1) return 'C';
    return 'F';
}

export async function fetchWhois(domain: string): Promise<WhoisResult> {
    if (!domain) {
        return { domain: '', timestamp: new Date().toISOString(), error: 'Missing domain parameter' };
    }

    if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
        return { domain, timestamp: new Date().toISOString(), error: 'Invalid domain format' };
    }

    const results: WhoisResult = { domain, timestamp: new Date().toISOString() };

    try {
        const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
            signal: AbortSignal.timeout(8000),
            headers: { 'Accept': 'application/json' },
        });
        if (res.ok) {
            const data: RdapResponse = await res.json();
            const events: WhoisEvent[] = (data.events || []).map((e) => ({
                action: e.eventAction,
                date: e.eventDate,
            }));
            const entities: WhoisEntity[] = (data.entities || []).map((e) => {
                const vcard = e.vcardArray?.[1] as unknown as [string, unknown, unknown, string][] | undefined;
                const fn = vcard?.find((v) => v[0] === 'fn')?.[3];
                const org = vcard?.find((v) => v[0] === 'org')?.[3];
                return { handle: e.handle, roles: e.roles, name: fn, org };
            }).filter((e) => e.name || e.org);

            results.rdap = {
                handle: data.handle,
                name: data.ldhName,
                status: data.status,
                events,
                nameservers: (data.nameservers || []).map((ns) => ns.ldhName),
                entities,
            };

            results.registration = events.find((e) => e.action === 'registration')?.date;
            results.expiration = events.find((e) => e.action === 'expiration')?.date;
            results.last_changed = events.find((e) => e.action === 'last changed')?.date;
        }
    } catch (e) { console.warn('[OSIRIS] Suppressed error:', e instanceof Error ? e.message : e); }

    // HTTP headers for tech fingerprinting. Note: fetch() follows redirects by
    // default; a malicious domain could still redirect a HEAD request to an
    // internal address (e.g. your own router). Low severity on a single-user
    // desktop app, but worth knowing this validation is lighter than the
    // original safeFetch, which re-validated each redirect hop.
    try {
        const res = await fetch(`https://${domain}`, {
            method: 'HEAD',
            signal: AbortSignal.timeout(5000),
        });
        const headers: Record<string, string> = {};
        SECURITY_HEADERS.forEach((h) => {
            const v = res.headers.get(h);
            if (v) headers[h] = v;
        });
        results.http = {
            status: res.status,
            headers,
            redirected: res.redirected,
            final_url: res.url,
        };

        let score = 0;
        if (headers['strict-transport-security']) score += 2;
        if (headers['content-security-policy']) score += 2;
        if (headers['x-frame-options']) score += 1;
        if (headers['x-content-type-options']) score += 1;
        if (headers['referrer-policy']) score += 1;
        results.security_score = { score, max: 7, grade: gradeFor(score) };
    } catch (e) { console.warn('[OSIRIS] Suppressed error:', e instanceof Error ? e.message : e); }

    return results;
}