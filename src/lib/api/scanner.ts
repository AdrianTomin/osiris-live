const SCANNER_URL = process.env.NEXT_PUBLIC_SCANNER_URL || '';
const SCANNER_KEY = process.env.NEXT_PUBLIC_SCANNER_KEY || '';

const ALLOWED_SCANS: Record<string, { endpoint: string; timeout: number }> = {
    quick:      { endpoint: '/scan/quick',      timeout: 15000 },
    ssl:        { endpoint: '/scan/ssl',        timeout: 10000 },
    headers:    { endpoint: '/scan/headers',    timeout: 10000 },
    rdns:       { endpoint: '/scan/rdns',       timeout: 8000  },
    subdomains: { endpoint: '/scan/subdomains', timeout: 15000 },
    tech:       { endpoint: '/scan/tech',       timeout: 15000 },
    whois:      { endpoint: '/scan/whois',      timeout: 10000 },
    geoloc:     { endpoint: '/scan/geoloc',     timeout: 8000  },
    vuln:       { endpoint: '/scan/vuln',       timeout: 90000 },
};

// REMOVED from availability (kept from original): deep, ports, banner, traceroute
// These require an authenticated/trusted context — deep scans 65,535 ports,
// ports allows arbitrary ranges, banner harvests software versions, and
// traceroute reveals hosting infrastructure. Only re-enable these if the
// scanner backend itself gates them behind real auth.

export interface ScannerResult {
    error?: string;
    hint?: string;
    detail?: string;
    available_scans?: string[];
    [key: string]: unknown;
}

export async function fetchScanner(target: string, scanType: string = 'quick'): Promise<ScannerResult> {
    if (!SCANNER_KEY || !SCANNER_URL) {
        return {
            error: 'Scanner not configured',
            hint: 'Set NEXT_PUBLIC_SCANNER_URL and NEXT_PUBLIC_SCANNER_KEY in .env.local if you run a self-hosted scanner backend',
        };
    }

    const trimmedTarget = target?.trim();
    if (!trimmedTarget) {
        return { error: 'Missing target parameter' };
    }

    // NOTE: the original SSRF/host validation (validateHost from ssrf-guard)
    // is not reproduced here. That check protected a *shared* server from being
    // used to attack internal infrastructure on its network. Here, the request
    // still leaves your machine toward SCANNER_URL — a backend you configured
    // yourself — so the trust model is different, but if SCANNER_URL is ever
    // something other than infrastructure you fully control, add target
    // validation back before enabling this.

    const scanConfig = ALLOWED_SCANS[scanType];
    if (!scanConfig) {
        return {
            error: 'Scan type not available',
            detail: `"${scanType}" is restricted. Available: ${Object.keys(ALLOWED_SCANS).join(', ')}`,
            available_scans: Object.keys(ALLOWED_SCANS),
        };
    }

    try {
        const params = new URLSearchParams({ key: SCANNER_KEY, target: trimmedTarget });
        const res = await fetch(`${SCANNER_URL}${scanConfig.endpoint}?${params.toString()}`, {
            signal: AbortSignal.timeout(scanConfig.timeout),
        });
        const data = await res.json();
        return data;
    } catch (e) {
        return {
            error: 'Scanner unreachable',
            detail: e instanceof Error ? e.message : 'Unknown error',
        };
    }
}