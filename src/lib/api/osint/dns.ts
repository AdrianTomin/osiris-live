import { fetch } from '@/lib/api/http';

interface GoogleDnsAnswer {
    name: string;
    type: number;
    TTL: number;
    data: string;
}

interface GoogleDnsResponse {
    Status: number;
    Answer?: GoogleDnsAnswer[];
}

export interface DnsRecord {
    name: string;
    type: number;
    ttl: number;
    data: string;
}

export interface DnsResult {
    domain: string;
    records: Record<string, DnsRecord[]>;
    summary?: {
        ip_addresses: string[];
        mail_servers: string[];
        nameservers: string[];
        total_records: number;
    };
    timestamp: string;
    error?: string;
}

const RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'];

export async function fetchDns(domain: string): Promise<DnsResult> {
    if (!domain) {
        return { domain: '', records: {}, timestamp: new Date().toISOString(), error: 'Missing domain parameter' };
    }

    if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
        return { domain, records: {}, timestamp: new Date().toISOString(), error: 'Invalid domain format' };
    }

    try {
        const results: DnsResult = { domain, records: {}, timestamp: new Date().toISOString() };

        const lookups = await Promise.allSettled(
            RECORD_TYPES.map(async (type) => {
                const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`, {
                    signal: AbortSignal.timeout(5000),
                    headers: { 'Accept': 'application/json' },
                });
                if (res.ok) {
                    const data: GoogleDnsResponse = await res.json();
                    return { type, answers: data.Answer || [], status: data.Status };
                }
                return { type, answers: [] as GoogleDnsAnswer[], status: -1 };
            })
        );

        for (const result of lookups) {
            if (result.status === 'fulfilled') {
                const { type, answers } = result.value;
                results.records[type] = answers.map((a) => ({
                    name: a.name,
                    type: a.type,
                    ttl: a.TTL,
                    data: a.data,
                }));
            }
        }

        const aRecords = results.records.A || [];
        const mxRecords = results.records.MX || [];
        const nsRecords = results.records.NS || [];

        results.summary = {
            ip_addresses: aRecords.map((r) => r.data),
            mail_servers: mxRecords.map((r) => r.data),
            nameservers: nsRecords.map((r) => r.data),
            total_records: Object.values(results.records).flat().length,
        };

        return results;
    } catch {
        return { domain, records: {}, timestamp: new Date().toISOString(), error: 'DNS lookup failed' };
    }
}