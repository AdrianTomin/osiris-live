import { fetch } from '@/lib/api/http';

export interface FrontlinesResult {
    frontlines: unknown | null;
    timestamp?: string;
    error?: string;
}

export async function fetchFrontlines(): Promise<FrontlinesResult> {
    try {
        const url = 'https://deepstatemap.live/api/history/last';
        const res = await fetch(url, {
            signal: AbortSignal.timeout(10000),
        });

        if (!res.ok) {
            return { frontlines: null, error: 'DeepState unavailable' };
        }

        const data: unknown = await res.json();

        return {
            frontlines: data,
            timestamp: new Date().toISOString(),
        };
    } catch (error) {
        console.error('Frontlines fetch error:', error);
        return { frontlines: null, error: 'Failed to fetch frontline data' };
    }
}