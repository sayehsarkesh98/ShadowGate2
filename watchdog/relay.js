// probe-relay: auth-gated, workers.dev-only health-probe relay.
// Purpose: give the watchdog a FOREIGN-account vantage point — Cloudflare
// blocks same-account workers.dev fetches from inside a Worker (instant
// 404 / error 1042), so the watchdog's own target is probed through here.
const ALLOWED_SUFFIX = '.workers.dev';
function json(obj, status) {
    return new Response(JSON.stringify(obj), { status: status || 200, headers: { 'content-type': 'application/json' } });
}
export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        if ((request.headers.get('Authorization') || '') !== 'Bearer ' + env.RELAY_KEY)
            return json({ error: 'unauthorized' }, 401);
        if (url.pathname !== '/probe') return json({ error: 'not found' }, 404);
        const u = url.searchParams.get('u') || '';
        let parsed;
        try { parsed = new URL(u); } catch (e) { return json({ error: 'bad url' }, 400); }
        if (parsed.protocol !== 'https:' || !parsed.hostname.endsWith(ALLOWED_SUFFIX))
            return json({ error: 'host not allowed' }, 403);
        try {
            const ctl = new AbortController();
            setTimeout(() => ctl.abort(), 10000);
            const t0 = Date.now();
            const r = await fetch(parsed.href, { signal: ctl.signal, redirect: 'manual' });
            const txt = await r.text().catch(() => '');
            return json({ status: r.status, head: txt.slice(0, 120), ms: Date.now() - t0 });
        } catch (e) {
            return json({ status: 0, error: String(e && e.message || e) });
        }
    }
};
