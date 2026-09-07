import { fetch } from '@/lib/api/http';

interface CrtShCertificate {
    id: number;
    issuer_name: string;
    common_name: string;
    name_value: string;
    not_before: string;
    not_after: string;
    serial_number: string;
}

export interface CertRecord {
    id: number;
    issuer: string;
    common_name: string;
    name_value: string;
    not_before: string;
    not_after: string;
    serial: string;
}

export interface CertsResult {
    domain: string;
    certificates: CertRecord[];
    subdomains: string[];
    total_certs?: number;
    unique_subdomains?: number;
    timestamp: string;
    error?: string;
}

export async function fetchCerts(domain: string): Promise<CertsResult> {
    if (!domain) {
        return { domain: '', certificates: [], subdomains: [], timestamp: new Date().toISOString(), error: 'Missing domain parameter' };
    }

    if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
        return { domain, certificates: [], subdomains: [], timestamp: new Date().toISOString(), error: 'Invalid domain format' };
    }

    try {
        const res = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, {
            signal: AbortSignal.timeout(10000),
            headers: { 'User-Agent': 'Osiris-OSINT/3.0' },
        });

        if (!res.ok) {
            return { domain, certificates: [], subdomains: [], timestamp: new Date().toISOString(), error: 'crt.sh unavailable' };
        }

        const certs: CrtShCertificate[] = await res.json();

        const seen = new Set<string>();
        const subdomains = new Set<string>();
        const uniqueCerts: CertRecord[] = [];

        for (const cert of certs.slice(0, 200)) {
            const key = `${cert.common_name}-${cert.serial_number}`;
            if (seen.has(key)) continue;
            seen.add(key);

            const name = cert.name_value || '';
            name.split('\n').forEach((n: string) => {
                const clean = n.trim().replace(/^\*\./, '');
                if (clean.endsWith(domain)) subdomains.add(clean);
            });

            uniqueCerts.push({
                id: cert.id,
                issuer: cert.issuer_name,
                common_name: cert.common_name,
                name_value: cert.name_value,
                not_before: cert.not_before,
                not_after: cert.not_after,
                serial: cert.serial_number,
            });
        }

        return {
            domain,
            certificates: uniqueCerts.slice(0, 50),
            subdomains: Array.from(subdomains).sort(),
            total_certs: certs.length,
            unique_subdomains: subdomains.size,
            timestamp: new Date().toISOString(),
        };
    } catch {
        return { domain, certificates: [], subdomains: [], timestamp: new Date().toISOString(), error: 'Lookup failed' };
    }
}