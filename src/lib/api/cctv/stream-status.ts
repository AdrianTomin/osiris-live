export interface StreamStatus {
    available: boolean | null;
    blocked: boolean | null;
    provider?: string;
    reason?: string;
}

const RTSP_BLOCKED = /temporarily limited|Top up/i;

export async function checkStreamStatus(url: string): Promise<StreamStatus> {
    if (!url || !/rtsp\.me\/embed/i.test(url)) {
        return { available: false, blocked: false, reason: 'not_rtsp_me' };
    }

    try {
        const res = await fetch(url, {
            signal: AbortSignal.timeout(8000),
            headers: {
                'User-Agent': 'Mozilla/5.0 (compatible; OSIRIS/1.0; +https://github.com/simplifaisoul/osiris)',
                Accept: 'text/html,application/xhtml+xml',
            },
        });

        if (!res.ok) {
            return { available: false, blocked: true, provider: 'rtsp.me' };
        }

        const html = await res.text();
        const blocked = RTSP_BLOCKED.test(html);

        return { available: !blocked, blocked, provider: 'rtsp.me' };
    } catch {
        return { available: null, blocked: null, provider: 'rtsp.me' };
    }
}