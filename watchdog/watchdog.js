// shadowgate-watchdog: health-check + auto-recovery engine for ShadowGate workers.
// Runs on account f8e142a5 (lulupoooo). Storage: KV (watchdog-kv).
// Secrets: CF_TOKENS = {"<account_id>":"<api_token>", ...}, WD_ADMIN = <bearer for admin API>.
//
// KV schema:
//   targets/<id>   JSON full target {id, account_id, script, hostname, enabled, auto_heal,
//                    admin_secret, profile{compatibility_date, compatibility_flags, vars, d1, kv, cron}}
//   bundle/current JSON meta {sha256, bytes, version, at}
//   bundle/current.js  raw worker source (the shadowgate bundle)
//   bundle/prev.js     previous bundle (rollback copy)
//   state/<id>     JSON {day, count, cooldown_until, last_status, last_checked}
//   events         JSON array (newest first, max 12) of status changes / heal results
//
// Guards: double-probe confirmation (30s apart), per-target 15min cooldown, max 6 heals/day,
//         abort if ALL targets are down at once (CF-side or bad-bundle situation), bundle
//         must contain "export default" before upload, verify bindings + probe after heal,
//         best-effort before/after D1 UUID snapshot to prove data untouched.

const CONFIRM_MS = 30000;       // wait between the two 1101 probes
const COOLDOWN_MS = 15 * 60 * 1000;
const MAX_HEALS_PER_DAY = 6;
const PROBE_TIMEOUT_MS = 10000;
const MAX_EVENTS = 12;

function jsonRes(obj, status) {
    return new Response(JSON.stringify(obj, null, 1), { status: status || 200, headers: { 'content-type': 'application/json' } });
}
async function kvJson(kv, key, dflt) {
    const v = await kv.get(key);
    if (v == null) return dflt;
    try { return JSON.parse(v); } catch (e) { return dflt; }
}
async function pushEvent(env, ev) {
    ev.t = new Date().toISOString();
    let list = (await kvJson(env.KV, 'events', [])) || [];
    list.unshift(ev);
    list = list.slice(0, MAX_EVENTS);
    await env.KV.put('events', JSON.stringify(list));
}
async function listTargets(env) {
    const k = await env.KV.list({ prefix: 'targets/' });
    const out = [];
    for (const key of k.keys) {
        const t = await kvJson(env.KV, key.name, null);
        if (t) out.push(t);
    }
    return out;
}
async function probe(url) {
    const t0 = Date.now();
    try {
        const ctl = new AbortController();
        const to = setTimeout(() => ctl.abort(), PROBE_TIMEOUT_MS);
        const r = await fetch(url, { signal: ctl.signal, redirect: 'manual' });
        clearTimeout(to);
        const txt = await r.text().catch(() => '');
        const is1101 = r.status === 500 && txt.indexOf('error code: 1101') >= 0;
        return { ok: !is1101 && r.status >= 200 && r.status < 500, status: r.status, is1101, ms: Date.now() - t0, head: txt.slice(0, 80) };
    } catch (e) {
        return { ok: false, status: 0, is1101: false, error: String(e && e.message || e), ms: Date.now() - t0 };
    }
}
function dayNow() { return new Date().toISOString().slice(0, 10); }

async function d1Uuids(accountId, token, databaseId) {
    // best-effort snapshot of user UUIDs (returns null if permission/path unavailable)
    try {
        const r = await fetch('https://api.cloudflare.com/client/v4/accounts/' + accountId + '/d1/database/' + databaseId + '/query', {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
            body: JSON.stringify({ sql: 'SELECT uuid FROM users ORDER BY uuid' })
        });
        const d = await r.json();
        if (!d.success || !d.result || !d.result[0]) return null;
        return (d.result[0].results || []).map(x => x.uuid).sort();
    } catch (e) { return null; }
}

async function healTarget(env, target, reason) {
    const ev = { target: target.id, action: 'heal', reason: reason, steps: [] };
    let tokens = {};
    try { tokens = JSON.parse(env.CF_TOKENS || '{}'); } catch (e) { }
    const token = tokens[target.account_id];
    if (!token) { ev.ok = false; ev.error = 'no api token for account ' + target.account_id; await pushEvent(env, ev); return ev; }
    const p = target.profile;
    const name = target.script;
    const base = 'https://api.cloudflare.com/client/v4/accounts/' + target.account_id + '/workers/scripts/' + name;
    try {
        // 0) bundle sanity
        const code = await env.KV.get('bundle/current.js');
        if (!code || code.indexOf('export default') < 0) { ev.ok = false; ev.error = 'bundle missing or invalid'; await pushEvent(env, ev); return ev; }
        // 1) pre-heal D1 uuid snapshot (best effort)
        const uuidsBefore = p.d1 ? await d1Uuids(target.account_id, token, p.d1.database_id) : null;
        ev.steps.push('uuids_before=' + (uuidsBefore ? uuidsBefore.length : 'skip'));
        // 2) DELETE (404 tolerated)
        let r = await fetch(base, { method: 'DELETE', headers: { 'Authorization': 'Bearer ' + token } });
        ev.steps.push('delete=' + r.status);
        if (r.status !== 200 && r.status !== 404) { ev.ok = false; ev.error = 'delete failed ' + r.status; await pushEvent(env, ev); return ev; }
        // 3) multipart redeploy from stored bundle
        const bindings = [];
        for (const k of Object.keys(p.vars || {})) bindings.push({ type: 'plain_text', name: k, text: p.vars[k] });
        if (p.kv) bindings.push({ type: 'kv_namespace', name: 'KV', namespace_id: p.kv.id });
        if (p.d1) bindings.push({ type: 'd1', name: 'DB', database_id: p.d1.database_id });
        const meta = {
            main_module: 'index',
            compatibility_date: p.compatibility_date,
            compatibility_flags: p.compatibility_flags || [],
            bindings: bindings
        };
        const fd = new FormData();
        fd.append('metadata', new Blob([JSON.stringify(meta)], { type: 'application/json' }));
        fd.append('index', new Blob([code], { type: 'application/javascript+module' }));
        r = await fetch(base, { method: 'PUT', headers: { 'Authorization': 'Bearer ' + token }, body: fd });
        const rj = await r.json().catch(() => ({}));
        ev.steps.push('upload=' + r.status + (r.success === false || rj.success === false ? ':' + JSON.stringify((rj.errors || []).slice(0, 1)) : ''));
        if (!r.ok || rj.success === false) { ev.ok = false; ev.error = 'upload failed'; await pushEvent(env, ev); return ev; }
        // 3b) activate workers.dev route — raw API uploads leave the subdomain route
        // OFF while wrangler turns it ON; without this the healed host 404s forever.
        let sd = await fetch(base + '/subdomain', { method: 'POST', headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: true, previews_enabled: true }) });
        if (sd.status >= 400) sd = await fetch(base + '/subdomain', { method: 'PUT', headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: true, previews_enabled: true }) });
        ev.steps.push('subdomain=' + sd.status);
        // 4) ADMIN secret (value lives only in the KV profile, never in code)
        if (!target.admin_secret) { ev.ok = false; ev.error = 'target.admin_secret missing in profile'; await pushEvent(env, ev); return ev; }
        r = await fetch(base + '/secrets', {
            method: 'PUT', headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: 'ADMIN', text: target.admin_secret, type: 'secret_text' })
        });
        ev.steps.push('admin=' + r.status);
        if (r.status !== 200 && r.status !== 201) { ev.ok = false; ev.error = 'admin secret failed'; await pushEvent(env, ev); return ev; }
        // 5) cron schedule (bare-array body — the only shape the API accepts)
        r = await fetch(base + '/schedules', {
            method: 'PUT', headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
            body: JSON.stringify([{ cron: p.cron || '0 0 * * *' }])
        });
        ev.steps.push('cron=' + r.status);
        if (r.status !== 200) { ev.ok = false; ev.error = 'schedule failed'; await pushEvent(env, ev); return ev; }
        // 6) verify: settings bindings + live probe
        r = await fetch(base + '/settings', { headers: { 'Authorization': 'Bearer ' + token } });
        const st = await r.json().catch(() => ({}));
        const gotB = ((st.result || {}).bindings || []).map(b => b.type).sort().join(',');
        ev.steps.push('bindings=' + gotB);
        let v = { status: 0, ok: false, is1101: true };
        for (let i = 0; i < 8; i++) {
            await new Promise(res => setTimeout(res, 5000));
            v = await probeTarget(env, target);
            ev.steps.push('probe_try' + (i + 1) + '=' + v.status);
            if (v.status >= 200 && v.status < 400) break;
        }
        // 7) post-heal uuid snapshot
        const uuidsAfter = p.d1 ? await d1Uuids(target.account_id, token, p.d1.database_id) : null;
        if (uuidsBefore && uuidsAfter) ev.uuids_unchanged = JSON.stringify(uuidsBefore) === JSON.stringify(uuidsAfter);
        ev.steps.push('uuids_after=' + (uuidsAfter ? uuidsAfter.length : 'skip'));
        ev.ok = v.status >= 200 && v.status < 400;
        if (ev.ok) {
            const stt = await kvJson(env.KV, 'state/' + target.id, {});
            stt.cooldown_until = Date.now() + COOLDOWN_MS;
            if (stt.day !== dayNow()) { stt.day = dayNow(); stt.count = 0; }
            stt.count = (stt.count || 0) + 1;
            stt.last_status = 'HEALED';
            await env.KV.put('state/' + target.id, JSON.stringify(stt));
        }
    } catch (e) {
        ev.ok = false; ev.error = String(e && e.message || e);
    }
    await pushEvent(env, ev);
    return ev;
}

// Same-account workers.dev fetches from inside a Worker are blocked by
// Cloudflare (instant 404 / error 1042) — targets on THIS account are probed
// through the foreign-account probe-relay instead (target.probe_via).
async function probeTarget(env, target) {
    if (target.probe_via) {
        try {
            const r = await fetch(target.probe_via + '/probe?u=' + encodeURIComponent('https://' + target.hostname + '/'), {
                headers: { 'Authorization': 'Bearer ' + env.RELAY_KEY },
                redirect: 'manual'
            });
            const j = await r.json();
            const status = (j && j.status) || 0;
            const head = (j && j.head) || '';
            return { ok: status >= 200 && status < 400, status: status, is1101: status === 500 && head.indexOf('error code: 1101') >= 0, ms: j && j.ms, head: head.slice(0, 80), via: 'relay' };
        } catch (e) {
            return { ok: false, status: 0, is1101: false, error: 'relay: ' + String(e && e.message || e) };
        }
    }
    return probe('https://' + target.hostname + '/');
}

async function checkTarget(env, target, opts) {
    const out = { target: target.id, auto: !opts || !opts.manual };
    const first = await probeTarget(env, target);
    out.first = first.status || first.error;
    if (first.status === 0) { await pushEvent(env, { target: target.id, action: 'probe_error', error: first.error || 'network' }); return { status: 'PROBE_ERROR', first: first.error || 'network' }; }
    if (first.status >= 200 && first.status < 400) {
        // status only written when it changes (KV free tier write budget)
        const stt = await kvJson(env.KV, 'state/' + target.id, {});
        if (stt.last_status !== 'OK') {
            const hadState = !!stt.last_status;
            stt.last_status = 'OK'; stt.last_checked = Date.now();
            await env.KV.put('state/' + target.id, JSON.stringify(stt));
            if (hadState && first.ok) await pushEvent(env, { target: target.id, action: 'recovered_observed', status: first.status });
        }
        return { status: 'OK', first: first.status, detail: first };
    }
    if (!first.is1101) {
        const sttU = await kvJson(env.KV, 'state/' + target.id, {});
        if (sttU.last_status !== 'UNHEALTHY_' + first.status) {
            sttU.last_status = 'UNHEALTHY_' + first.status; sttU.last_checked = Date.now();
            await env.KV.put('state/' + target.id, JSON.stringify(sttU));
            await pushEvent(env, { target: target.id, action: 'unhealthy_status', status: first.status });
        }
        return { status: 'UNHEALTHY_' + first.status, first: first.status };
    }
    await new Promise(res => setTimeout(res, CONFIRM_MS));
    const second = await probeTarget(env, target);
    out.second = second.status || second.error;
    if (!second.is1101) {
        await pushEvent(env, { target: target.id, action: 'flaky_1101_not_confirmed', first: first.status, second: second.status });
        return { status: 'FLAKY', detail: second };
    }
    // confirmed 1101 twice
    if (!(opts && opts.force)) {
        const stt = await kvJson(env.KV, 'state/' + target.id, {});
        if (stt.day !== dayNow()) { stt.day = dayNow(); stt.count = 0; }
        if (stt.cooldown_until && Date.now() < stt.cooldown_until) {
            await pushEvent(env, { target: target.id, action: '1101_confirmed_but_cooldown' });
            return { status: '1101_COOLDOWN' };
        }
        if ((stt.count || 0) >= MAX_HEALS_PER_DAY) {
            await pushEvent(env, { target: target.id, action: '1101_confirmed_but_daily_limit', count: stt.count });
            return { status: '1101_DAILY_LIMIT' };
        }
    }
    if (!target.auto_heal && !(opts && opts.force)) {
        await pushEvent(env, { target: target.id, action: '1101_confirmed_monitor_only' });
        return { status: '1101_MONITOR_ONLY' };
    }
    const healed = await healTarget(env, target, opts && opts.force ? 'manual' : 'auto');
    return { status: healed.ok ? 'HEALED' : 'HEAL_FAILED', heal: healed };
}

async function runChecks(env) {
    const targets = (await listTargets(env)).filter(t => t.enabled);
    // positive proof-of-life marker: written every cron cycle (one KV write / 5 min)
    await env.KV.put('state/_lastcycle', JSON.stringify({ at: new Date().toISOString(), targets: targets.length }));
    // global guard: probe everybody first; if ALL are broken it smells like a CF-side or
    // bundle-wide problem — never mass-heal in that state
    const probes = [];
    for (const t of targets) probes.push(await probeTarget(env, t));
    const broken = targets.filter((t, i) => probes[i].is1101);
    if (targets.length > 1 && broken.length === targets.length) {
        await pushEvent(env, { action: 'ALL_TARGETS_1101_aborting_heal', targets: broken.map(b => b.id) });
        return { aborted: 'all_down' };
    }
    const results = [];
    for (const t of broken) results.push(await checkTarget(env, t, { skipFirstProbe: true }));
    return { checked: targets.length, broken: broken.length, results };
}

export default {
    async scheduled(event, env, ctx) {
        ctx.waitUntil(runChecks(env).catch(e => pushEvent(env, { action: 'runner_error', error: String(e) })));
    },
    async fetch(request, env) {
        const url = new URL(request.url);
        const path = url.pathname;
        const auth = request.headers.get('Authorization') || '';
        if (auth !== 'Bearer ' + env.WD_ADMIN) return jsonRes({ error: 'unauthorized' }, 401);
        try {
            if (path === '/status' && request.method === 'GET') {
                const targets = await listTargets(env);
                const merged = [];
                for (const t of targets) merged.push({ id: t.id, hostname: t.hostname, enabled: t.enabled, auto_heal: t.auto_heal, state: await kvJson(env.KV, 'state/' + t.id, {}) });
                return jsonRes({ targets: merged, events: await kvJson(env.KV, 'events', []), bundle: await kvJson(env.KV, 'bundle/current', null), lastcycle: await kvJson(env.KV, 'state/_lastcycle', null) });
            }
            if (path === '/targets' && request.method === 'GET') return jsonRes({ targets: await listTargets(env) });
            if (path.startsWith('/targets/') && (request.method === 'POST' || request.method === 'PUT')) {
                const t = await request.json();
                t.id = path.slice('/targets/'.length);
                if (!t.account_id || !t.script || !t.hostname) return jsonRes({ error: 'account_id, script, hostname required' }, 400);
                t.enabled = t.enabled !== false;
                t.auto_heal = !!t.auto_heal;
                await env.KV.put('targets/' + t.id, JSON.stringify(t));
                await pushEvent(env, { action: 'target_upserted', target: t.id, auto_heal: t.auto_heal });
                return jsonRes({ ok: true, id: t.id });
            }
            if (path === '/bundle' && request.method === 'POST') {
                const body = await request.json();
                if (!body.code || body.code.indexOf('export default') < 0) return jsonRes({ error: 'code must contain export default' }, 400);
                const prev = await env.KV.get('bundle/current.js');
                if (prev) await env.KV.put('bundle/prev.js', prev);
                await env.KV.put('bundle/current.js', body.code);
                const meta = { bytes: body.code.length, version: body.version || 'unversioned', at: new Date().toISOString() };
                await env.KV.put('bundle/current', JSON.stringify(meta));
                await pushEvent(env, { action: 'bundle_updated', version: meta.version, bytes: meta.bytes });
                return jsonRes({ ok: true, meta });
            }
            if (path.startsWith('/check/') && request.method === 'POST') {
                const id = path.slice('/check/'.length);
                const t = await kvJson(env.KV, 'targets/' + id, null);
                if (!t) return jsonRes({ error: 'unknown target' }, 404);
                return jsonRes(await checkTarget(env, t, { manual: true }));
            }
            if (path.startsWith('/heal/') && request.method === 'POST') {
                const id = path.slice('/heal/'.length);
                const t = await kvJson(env.KV, 'targets/' + id, null);
                if (!t) return jsonRes({ error: 'unknown target' }, 404);
                return jsonRes(await healTarget(env, t, 'manual-admin'));
            }
            if (path === '/debug' && request.method === 'GET') {
                const u = url.searchParams.get('u');
                if (!u) return jsonRes({ error: 'u required' }, 400);
                const modes = {
                    probe_opts: { redirect: 'manual' },
                    bare: {},
                    ua: { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36' } },
                    follow: { redirect: 'follow' }
                };
                const out = {};
                for (const k of Object.keys(modes)) {
                    try {
                        const t0 = Date.now();
                        const r = await fetch(u, modes[k]);
                        const txt = await r.text().catch(() => '');
                        out[k] = { status: r.status, ms: Date.now() - t0, head: txt.slice(0, 70) };
                    } catch (e) { out[k] = { err: String(e && e.message || e) }; }
                }
                return jsonRes({ url: u, out });
            }
            if (path === '/rollback-bundle' && request.method === 'POST') {
                const prev = await env.KV.get('bundle/prev.js');
                if (!prev) return jsonRes({ error: 'no prev bundle' }, 400);
                const cur = await env.KV.get('bundle/current.js');
                await env.KV.put('bundle/current.js', prev);
                if (cur) await env.KV.put('bundle/prev.js', cur);
                await pushEvent(env, { action: 'bundle_rolled_back' });
                return jsonRes({ ok: true });
            }
            return jsonRes({ error: 'not found' }, 404);
        } catch (e) {
            return jsonRes({ error: String(e && e.message || e) }, 500);
        }
    }
};
