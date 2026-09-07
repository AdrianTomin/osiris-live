interface EonetGeometry {
    type: string;
    coordinates: number[];
    date?: string;
}

interface EonetCategory {
    id: string;
    title?: string;
}

interface EonetSource {
    url?: string;
}

interface EonetEvent {
    id: string;
    title: string;
    categories?: EonetCategory[];
    geometry?: EonetGeometry[];
    sources?: EonetSource[];
}

interface EonetResponse {
    events?: EonetEvent[];
}

export interface WeatherEvent {
    id: string;
    title: string;
    category: string;
    type: string;
    icon: string;
    severity: 'low' | 'medium' | 'high';
    lat: number;
    lng: number;
    date?: string;
    source: string;
}

export async function fetchWeatherEvents(): Promise<{
    events: WeatherEvent[];
    total: number;
    timestamp: string;
    error?: string;
}> {
    try {
        const res = await fetch('https://eonet.gsfc.nasa.gov/api/v3/events?status=open&limit=100', {
            signal: AbortSignal.timeout(10000),
        });

        if (!res.ok) throw new Error(`NASA EONET API returned ${res.status}`);

        const data: EonetResponse = await res.json();
        const events: WeatherEvent[] = [];

        for (const event of data.events || []) {
            const geom = event.geometry && event.geometry.length > 0 ? event.geometry[event.geometry.length - 1] : null;
            if (!geom || geom.type !== 'Point') continue;

            const category = event.categories?.[0]?.id || 'unknown';

            if (category === 'wildfires') continue;

            let typeLabel = 'Event';
            let icon = 'alert';
            let severity: 'low' | 'medium' | 'high' = 'low';

            if (category === 'severeStorms') {
                typeLabel = 'Severe Storm';
                icon = 'cyclone';
                severity = 'high';
            } else if (category === 'volcanoes') {
                typeLabel = 'Volcano Eruption';
                icon = 'volcano';
                severity = 'high';
            } else if (category === 'seaIce') {
                typeLabel = 'Iceberg / Sea Ice';
                icon = 'ice';
                severity = 'medium';
            } else if (category === 'earthquakes') {
                continue;
            } else {
                typeLabel = event.categories?.[0]?.title || 'Anomaly';
            }

            events.push({
                id: event.id,
                title: event.title,
                category,
                type: typeLabel,
                icon,
                severity,
                lat: geom.coordinates[1],
                lng: geom.coordinates[0],
                date: geom.date,
                source: event.sources?.[0]?.url || 'NASA EONET',
            });
        }

        return { events, total: events.length, timestamp: new Date().toISOString() };
    } catch (error) {
        console.error('Weather API error:', error);
        return { events: [], total: 0, timestamp: new Date().toISOString(), error: 'Failed to fetch NASA EONET data' };
    }
}