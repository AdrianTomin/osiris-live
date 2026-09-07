import { fetch } from '@/lib/api/http';

interface KpEntry {
    kp_index?: string | number;
    Kp?: string | number;
    time_tag?: string;
}

interface RawAlert {
    product_id?: string;
    issue_datetime?: string;
    message?: string;
}

interface RawFlare {
    max_class?: string;
    begin_time?: string;
    max_time?: string;
    end_time?: string;
}

export interface SpaceWeatherAlert {
    id: string;
    issue_datetime: string;
    message: string;
}

export interface SolarFlare {
    class: string;
    begin: string;
    peak: string;
    end: string;
}

export interface SpaceWeatherResult {
    kp_index: number;
    storm_level: string;
    storm_color: string;
    kp_timestamp: string;
    alerts: SpaceWeatherAlert[];
    solar_flares: SolarFlare[];
    timestamp: string;
    error?: string;
}

export async function fetchSpaceWeather(): Promise<SpaceWeatherResult> {
    try {
        const [kpRes, alertsRes, flareRes] = await Promise.allSettled([
            fetch('https://services.swpc.noaa.gov/json/planetary_k_index_1m.json', {
                signal: AbortSignal.timeout(8000),
            }).then(r => r.json()) as Promise<KpEntry[]>,
            fetch('https://services.swpc.noaa.gov/json/alerts.json', {
                signal: AbortSignal.timeout(8000),
            }).then(r => r.json()) as Promise<RawAlert[]>,
            fetch('https://services.swpc.noaa.gov/json/goes/primary/xray-flares-latest.json', {
                signal: AbortSignal.timeout(8000),
            }).then(r => r.json()) as Promise<RawFlare[]>,
        ]);

        let kpIndex = 0;
        let kpTimestamp = '';
        if (kpRes.status === 'fulfilled' && Array.isArray(kpRes.value) && kpRes.value.length > 0) {
            const latest = kpRes.value[kpRes.value.length - 1];
            kpIndex = parseFloat(String(latest.kp_index ?? latest.Kp ?? 0));
            kpTimestamp = latest.time_tag || '';
        }

        let stormLevel = 'Quiet';
        let stormColor = '#00E676';
        if (kpIndex >= 8) { stormLevel = 'Extreme (G5)'; stormColor = '#FF1744'; }
        else if (kpIndex >= 7) { stormLevel = 'Severe (G4)'; stormColor = '#FF3D3D'; }
        else if (kpIndex >= 6) { stormLevel = 'Strong (G3)'; stormColor = '#FF9500'; }
        else if (kpIndex >= 5) { stormLevel = 'Moderate (G2)'; stormColor = '#FFD700'; }
        else if (kpIndex >= 4) { stormLevel = 'Minor (G1)'; stormColor = '#FFD700'; }
        else if (kpIndex >= 3) { stormLevel = 'Unsettled'; stormColor = '#D4AF37'; }

        const alerts: SpaceWeatherAlert[] = [];
        if (alertsRes.status === 'fulfilled' && Array.isArray(alertsRes.value)) {
            for (const alert of alertsRes.value.slice(0, 10)) {
                alerts.push({
                    id: alert.product_id || `alert-${Date.now()}`,
                    issue_datetime: alert.issue_datetime || '',
                    message: (alert.message || '').substring(0, 200),
                });
            }
        }

        const flares: SolarFlare[] = [];
        if (flareRes.status === 'fulfilled' && Array.isArray(flareRes.value)) {
            for (const flare of flareRes.value.slice(0, 5)) {
                if (!flare.max_class) continue;
                flares.push({
                    class: flare.max_class,
                    begin: flare.begin_time || '',
                    peak: flare.max_time || '',
                    end: flare.end_time || '',
                });
            }
        }

        return {
            kp_index: kpIndex,
            storm_level: stormLevel,
            storm_color: stormColor,
            kp_timestamp: kpTimestamp,
            alerts,
            solar_flares: flares,
            timestamp: new Date().toISOString(),
        };
    } catch (error) {
        console.error('Space Weather API error:', error);
        return {
            kp_index: 0,
            storm_level: 'Unknown',
            storm_color: '#555',
            kp_timestamp: '',
            alerts: [],
            solar_flares: [],
            timestamp: new Date().toISOString(),
            error: 'Failed to fetch space weather data',
        };
    }
}