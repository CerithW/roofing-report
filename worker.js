/**
 * J Randall Roofing — Xero CORS proxy (Cloudflare Worker)
 *
 * Xero's API does not send CORS headers, so a browser app cannot call it
 * directly. This worker forwards requests and adds CORS headers, and holds
 * the Xero client secret (set XERO_CLIENT_ID and XERO_CLIENT_SECRET as
 * Worker secrets — never put the secret in the front-end).
 *
 * Routes:
 *   POST /token        — OAuth token exchange / refresh (adds client credentials)
 *   GET  /connections  — proxy to https://api.xero.com/connections
 *   GET  /api/<path>   — proxy to https://api.xero.com/api.xro/2.0/<path>
 */

const ALLOWED_ORIGIN = 'https://cerithw.github.io';

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization,Xero-Tenant-Id',
    'Access-Control-Expose-Headers': 'Retry-After',
    'Access-Control-Max-Age': '86400',
  };
}

export default {
  async fetch(request, env) {
    const cors = corsHeaders();

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    const url = new URL(request.url);

    if (url.pathname === '/') {
      return new Response('ok', { status: 200, headers: cors });
    }

    // Fail CLOSED: cross-origin browser requests always carry Origin, so
    // anything without the exact allowed origin (including no Origin at all)
    // is rejected. Defense-in-depth alongside PKCE — not sufficient alone,
    // since non-browser clients can forge Origin.
    const origin = request.headers.get('Origin');
    if (origin !== ALLOWED_ORIGIN) {
      return new Response('Forbidden', { status: 403, headers: cors });
    }

    if (url.pathname === '/token' && request.method === 'POST') {
      const form = await request.formData();
      const grant = form.get('grant_type');
      const body = new URLSearchParams();
      body.set('client_id', env.XERO_CLIENT_ID);
      body.set('client_secret', env.XERO_CLIENT_SECRET);
      if (grant === 'authorization_code') {
        body.set('grant_type', 'authorization_code');
        body.set('code', form.get('code') || '');
        body.set('redirect_uri', form.get('redirect_uri') || '');
        body.set('code_verifier', form.get('code_verifier') || '');
      } else if (grant === 'refresh_token') {
        body.set('grant_type', 'refresh_token');
        body.set('refresh_token', form.get('refresh_token') || '');
      } else {
        return new Response(JSON.stringify({ error: 'unsupported_grant_type' }), {
          status: 400, headers: { ...cors, 'Content-Type': 'application/json' },
        });
      }
      const res = await fetch('https://identity.xero.com/connect/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
      });
      return new Response(await res.text(), {
        status: res.status, headers: { ...cors, 'Content-Type': 'application/json' },
      });
    }

    if (url.pathname === '/revoke' && request.method === 'POST') {
      const form = await request.formData();
      const res = await fetch('https://identity.xero.com/connect/revocation', {
        method: 'POST',
        headers: {
          'Authorization': 'Basic ' + btoa(env.XERO_CLIENT_ID + ':' + env.XERO_CLIENT_SECRET),
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ token: form.get('token') || '' }).toString(),
      });
      return new Response(null, { status: res.ok ? 200 : res.status, headers: cors });
    }

    if (url.pathname === '/connections' && request.method === 'GET') {
      const res = await fetch('https://api.xero.com/connections', {
        headers: {
          'Authorization': request.headers.get('Authorization') || '',
          'Accept': 'application/json',
        },
      });
      return new Response(await res.text(), {
        status: res.status, headers: { ...cors, 'Content-Type': 'application/json' },
      });
    }

    if (url.pathname.startsWith('/api/') && request.method === 'GET') {
      const target = 'https://api.xero.com/api.xro/2.0/' + url.pathname.slice(5) + url.search;
      const res = await fetch(target, {
        headers: {
          'Authorization': request.headers.get('Authorization') || '',
          'Xero-Tenant-Id': request.headers.get('Xero-Tenant-Id') || '',
          'Accept': 'application/json',
        },
      });
      const headers = { ...cors, 'Content-Type': res.headers.get('Content-Type') || 'application/json' };
      const retryAfter = res.headers.get('Retry-After');
      if (retryAfter) headers['Retry-After'] = retryAfter;
      return new Response(await res.text(), { status: res.status, headers });
    }

    return new Response('Not found', { status: 404, headers: cors });
  },
};
