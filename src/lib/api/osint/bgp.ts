import { fetch } from '@/lib/api/http';

interface BgpIpData {
    [key: string]: unknown;
}

interface BgpAsnData {
    [key: string]: unknown;
}

interface BgpPrefix {
    [key: string]: unknown;
}

interface BgpPeer {
    [key: string]: unknown;
}

interface BgpViewResponse<T> {
    status: string;
    data?: T;
}

export interface BgpLookupResult {
    query: string;
    timestamp: string;
    type?: 'ip' | 'asn';
    ip?: BgpIpData;
    asn?: BgpAsnData;
    prefixes?: {
        ipv4: BgpPrefix[];
        ipv6: BgpPrefix[];
        total_v4: number;
        total_v6: number;
    };
    peers?: {
        upstream: BgpPeer[];
        total: number;
    };
    error?: string;
}

export async function fetchBgp(query: string): Promise<BgpLookupResult> {
    if (!query) {
        return { query: '', timestamp: new Date().toISOString(), error: 'Missing query parameter (IP, ASN number, or prefix)' };
    }

    try {
        const results: BgpLookupResult = { query, timestamp: new Date().toISOString() };

        const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(query);
        const isASN = /^(AS)?\d+$/i.test(query);
        const asnNum = isASN ? query.replace(/^AS/i, '') : null;

        if (isIP) {
            const res = await fetch(`https://api.bgpview.io/ip/${query}`, {
                signal: AbortSignal.timeout(8000),
                headers: { 'Accept': 'application/json' },
            });
            if (res.ok) {
                const data: BgpViewResponse<BgpIpData> = await res.json();
                if (data.status === 'ok') {
                    results.ip = data.data;
                    results.type = 'ip';
                }
            }
        } else if (asnNum) {
            const [asnRes, prefixRes, peersRes] = await Promise.allSettled([
                fetch(`https://api.bgpview.io/asn/${asnNum}`, { signal: AbortSignal.timeout(8000) }),
                fetch(`https://api.bgpview.io/asn/${asnNum}/prefixes`, { signal: AbortSignal.timeout(8000) }),
                fetch(`https://api.bgpview.io/asn/${asnNum}/peers`, { signal: AbortSignal.timeout(8000) }),
            ]);

            if (asnRes.status === 'fulfilled' && asnRes.value.ok) {
                const d: BgpViewResponse<BgpAsnData> = await asnRes.value.json();
                if (d.status === 'ok') results.asn = d.data;
            }
            if (prefixRes.status === 'fulfilled' && prefixRes.value.ok) {
                const d: BgpViewResponse<{ ipv4_prefixes?: BgpPrefix[]; ipv6_prefixes?: BgpPrefix[] }> = await prefixRes.value.json();
                if (d.status === 'ok') {
                    results.prefixes = {
                        ipv4: (d.data?.ipv4_prefixes || []).slice(0, 20),
                        ipv6: (d.data?.ipv6_prefixes || []).slice(0, 10),
                        total_v4: d.data?.ipv4_prefixes?.length || 0,
                        total_v6: d.data?.ipv6_prefixes?.length || 0,
                    };
                }
            }
            if (peersRes.status === 'fulfilled' && peersRes.value.ok) {
                const d: BgpViewResponse<{ ipv4_peers?: BgpPeer[] }> = await peersRes.value.json();
                if (d.status === 'ok') {
                    results.peers = {
                        upstream: (d.data?.ipv4_peers || []).slice(0, 10),
                        total: d.data?.ipv4_peers?.length || 0,
                    };
                }
            }
            results.type = 'asn';
        } else {
            return { query, timestamp: new Date().toISOString(), error: 'Unrecognized query format. Use IP address or AS number.' };
        }

        return results;
    } catch {
        return { query, timestamp: new Date().toISOString(), error: 'BGP lookup failed' };
    }
}