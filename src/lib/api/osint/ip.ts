import { fetch } from '@/lib/api/http';

interface IpApiResponse {
    status: string;
    message?: string;
    country?: string;
    countryCode?: string;
    regionName?: string;
    city?: string;
    lat?: number;
    lon?: number;
    timezone?: string;
    isp?: string;
    org?: string;
    as?: string;
    asname?: string;
    mobile?: boolean;
    proxy?: boolean;
    hosting?: boolean;
}

export interface IpGeoInfo {
    country?: string;
    country_code?: string;
    region?: string;
    city?: string;
    lat?: number;
    lon?: number;
    timezone?: string;
    isp?: string;
    org?: string;
    as_number?: string;
    as_name?: string;
    is_mobile?: boolean;
    is_proxy?: boolean;
    is_hosting?: boolean;
}

export interface IpReputation {
    is_proxy: boolean;
    is_hosting: boolean;
    is_mobile: boolean;
    risk_level: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface IpLookupResult {
    ip: string;
    geo?: IpGeoInfo;
    reputation?: IpReputation;
    timestamp: string;
    error?: string;
}

function riskLevelFor(geo: IpGeoInfo | undefined): 'HIGH' | 'MEDIUM' | 'LOW' {
    if (geo?.is_proxy) return 'HIGH';
    if (geo?.is_hosting) return 'MEDIUM';
    return 'LOW';
}

export async function fetchIp(ip: string): Promise<IpLookupResult> {
    if (!ip) {
        return { ip: '', timestamp: new Date().toISOString(), error: 'Missing ip parameter' };
    }

    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6 = /^[0-9a-fA-F:]+$/;
    if (!ipv4.test(ip) && !ipv6.test(ip)) {
        return { ip, timestamp: new Date().toISOString(), error: 'Invalid IP format' };
    }

    try {
        const results: IpLookupResult = { ip, timestamp: new Date().toISOString() };

        try {
            const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,continent,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query`, {
                signal: AbortSignal.timeout(5000),
            });
            if (res.ok) {
                const geo: IpApiResponse = await res.json();
                if (geo.status === 'success') {
                    results.geo = {
                        country: geo.country,
                        country_code: geo.countryCode,
                        region: geo.regionName,
                        city: geo.city,
                        lat: geo.lat,
                        lon: geo.lon,
                        timezone: geo.timezone,
                        isp: geo.isp,
                        org: geo.org,
                        as_number: geo.as,
                        as_name: geo.asname,
                        is_mobile: geo.mobile,
                        is_proxy: geo.proxy,
                        is_hosting: geo.hosting,
                    };
                }
            }
        } catch (e) { console.warn('[OSIRIS] Suppressed error:', e instanceof Error ? e.message : e); }

        results.reputation = {
            is_proxy: results.geo?.is_proxy || false,
            is_hosting: results.geo?.is_hosting || false,
            is_mobile: results.geo?.is_mobile || false,
            risk_level: riskLevelFor(results.geo),
        };

        return results;
    } catch {
        return { ip, timestamp: new Date().toISOString(), error: 'IP lookup failed' };
    }
}