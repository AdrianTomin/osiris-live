import { fetch } from '@/lib/api/http';

interface NominatimAddress {
    city?: string;
    town?: string;
    village?: string;
    state?: string;
    region?: string;
    country?: string;
    country_code?: string;
}

interface NominatimResponse {
    address?: NominatimAddress;
    display_name?: string;
}

interface LocationInfo {
    city: string;
    state: string;
    country: string;
    country_code: string;
    display_name?: string;
}

interface RestCountryName {
    common?: string;
    official?: string;
}

interface RestCountryCurrency {
    name: string;
    symbol?: string;
}

interface RestCountryData {
    name?: RestCountryName;
    capital?: string[];
    population?: number;
    area?: number;
    region?: string;
    subregion?: string;
    languages?: Record<string, string>;
    currencies?: Record<string, RestCountryCurrency>;
    flag?: string;
    flags?: { svg?: string };
    timezones?: string[];
}

interface WikiSummary {
    title: string;
    extract?: string;
    thumbnail?: string;
}

interface WikiApiResponse {
    title: string;
    extract?: string;
    thumbnail?: { source?: string };
}

interface HeadOfState {
    name?: string;
    position: string;
}

interface WikidataBinding {
    leaderLabel?: { value: string };
    positionLabel?: { value: string };
}

interface WikidataResponse {
    results?: {
        bindings?: WikidataBinding[];
    };
}

export interface RegionDossierResult {
    coordinates: { lat: number; lng: number };
    location: LocationInfo;
    country: {
        name?: string;
        official_name?: string;
        capital?: string;
        population?: number;
        area?: number;
        region?: string;
        subregion?: string;
        languages: string[];
        currencies: string[];
        flag?: string;
        flag_url?: string;
        timezones?: string[];
    } | null;
    head_of_state: HeadOfState | null;
    wikipedia: WikiSummary | null;
    timestamp: string;
    error?: string;
}

export async function fetchRegionDossier(lat: number, lng: number): Promise<RegionDossierResult> {
    try {
        const geoRes = await fetch(
            `https://nominatim.openstreetmap.org/reverse?lat=${lat}&lon=${lng}&format=json&zoom=5&addressdetails=1`,
            {
                signal: AbortSignal.timeout(8000),
                headers: { 'User-Agent': 'OsirisIntelPlatform/1.0' },
            }
        );

        let countryName = '';
        let countryCode = '';
        let locationInfo: LocationInfo = { city: '', state: '', country: '', country_code: '' };

        if (geoRes.ok) {
            const geoData: NominatimResponse = await geoRes.json();
            const addr = geoData.address || {};
            countryName = addr.country || '';
            countryCode = addr.country_code?.toUpperCase() || '';
            locationInfo = {
                city: addr.city || addr.town || addr.village || '',
                state: addr.state || addr.region || '',
                country: countryName,
                country_code: countryCode,
                display_name: geoData.display_name,
            };
        }

        const [countryResult, wikiResult, hosResult] = await Promise.allSettled([
            (async (): Promise<RestCountryData | null> => {
                if (!countryCode) return null;
                try {
                    const res = await fetch(
                        `https://restcountries.com/v3.1/alpha/${countryCode}?fields=name,capital,population,area,region,subregion,languages,currencies,flag,flags,timezones`,
                        { signal: AbortSignal.timeout(5000) }
                    );
                    if (res.ok) return await res.json();
                } catch (e) { console.warn('[OSIRIS] Country fetch error:', e instanceof Error ? e.message : e); }
                return null;
            })(),

            (async (): Promise<WikiSummary | null> => {
                const wikiQuery = locationInfo.city || countryName;
                if (!wikiQuery) return null;
                try {
                    const res = await fetch(
                        `https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(wikiQuery)}`,
                        { signal: AbortSignal.timeout(5000) }
                    );
                    if (res.ok) {
                        const wiki: WikiApiResponse = await res.json();
                        return {
                            title: wiki.title,
                            extract: wiki.extract?.substring(0, 500),
                            thumbnail: wiki.thumbnail?.source,
                        };
                    }
                } catch (e) { console.warn('[OSIRIS] Wikipedia fetch error:', e instanceof Error ? e.message : e); }
                return null;
            })(),

            (async (): Promise<HeadOfState | null> => {
                if (!countryName) return null;
                try {
                    const safe = countryName.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
                    const sparql = `SELECT ?leader ?leaderLabel ?positionLabel WHERE {
            ?country wdt:P31 wd:Q6256;
                     rdfs:label "${safe}"@en;
                     wdt:P6 ?leader.
            OPTIONAL { ?leader wdt:P39 ?position. }
            SERVICE wikibase:label { bd:serviceParam wikibase:language "en". }
          } LIMIT 1`;
                    const res = await fetch(
                        `https://query.wikidata.org/sparql?format=json&query=${encodeURIComponent(sparql)}`,
                        {
                            signal: AbortSignal.timeout(5000),
                            headers: { 'User-Agent': 'OsirisIntelPlatform/1.0' },
                        }
                    );
                    if (res.ok) {
                        const wd: WikidataResponse = await res.json();
                        const binding = wd.results?.bindings?.[0];
                        if (binding) {
                            return {
                                name: binding.leaderLabel?.value,
                                position: binding.positionLabel?.value || 'Head of State',
                            };
                        }
                    }
                } catch (e) { console.warn('[OSIRIS] Wikidata fetch error:', e instanceof Error ? e.message : e); }
                return null;
            })(),
        ]);

        const countryData = countryResult.status === 'fulfilled' ? countryResult.value : null;
        const wikiSummary = wikiResult.status === 'fulfilled' ? wikiResult.value : null;
        const headOfState = hosResult.status === 'fulfilled' ? hosResult.value : null;

        return {
            coordinates: { lat, lng },
            location: locationInfo,
            country: countryData ? {
                name: countryData.name?.common,
                official_name: countryData.name?.official,
                capital: countryData.capital?.[0],
                population: countryData.population,
                area: countryData.area,
                region: countryData.region,
                subregion: countryData.subregion,
                languages: countryData.languages ? Object.values(countryData.languages) : [],
                currencies: countryData.currencies
                    ? Object.entries(countryData.currencies).map(([code, info]) => `${info.name} (${info.symbol || code})`)
                    : [],
                flag: countryData.flag,
                flag_url: countryData.flags?.svg,
                timezones: countryData.timezones,
            } : null,
            head_of_state: headOfState,
            wikipedia: wikiSummary,
            timestamp: new Date().toISOString(),
        };
    } catch (error) {
        console.error('Region dossier error:', error);
        return {
            coordinates: { lat, lng },
            location: { city: '', state: '', country: '', country_code: '' },
            country: null,
            head_of_state: null,
            wikipedia: null,
            timestamp: new Date().toISOString(),
            error: 'Failed to fetch region data',
        };
    }
}