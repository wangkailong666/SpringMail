/**
 * NovaMail Tracker — Cloudflare Worker
 *
 * Tracks email open events via 1x1 transparent pixel and stores
 * read statistics in R2.
 *
 * Endpoints:
 *   GET /track?e=<mail_id>&t=<token>&s=<hmac>  — Log open event, return pixel
 *   GET /stats?api_token=<key>&mail_id=<id> — Return aggregated stats
 *
 * Environment variables (wrangler.toml):
 *   STATS_API_TOKEN  — Secret token for accessing /stats endpoint
 *   HMAC_SECRET      — Shared secret for HMAC-SHA256 signature verification (M3-10)
 *   R2_BUCKET        — Bound R2 bucket (via wrangler.toml r2_buckets)
 */

/// <reference types="@cloudflare/workers-types" />

// 1x1 transparent GIF (43 bytes), base64 encoded
const PIXEL_BASE64 = 'R0lGODlhAQABAIAAAAAAAP///yH5BAAAAAAALAAAAAABAAEAAAICRAEAOw==';
const PIXEL_BYTES = Uint8Array.from(atob(PIXEL_BASE64), (c) => c.charCodeAt(0));

// Regex for token validation: 43 chars, base64url (A-Za-z0-9-_)
const TOKEN_RE = /^[A-Za-z0-9\-_]{43}$/;
const MAIL_ID_RE = /^\d+$/;

interface Env {
  TRACKER_BUCKET: R2Bucket;
  STATS_API_TOKEN: string;
  HMAC_SECRET?: string;
}

interface TrackEvent {
  mail_id: number;
  token: string;
  ip: string;
  country: string | null;
  user_agent: string;
  timestamp: number;
}

interface StatsResponse {
  mail_id: number;
  total_opens: number;
  first_opened_at: number | null;
  last_opened_at: number | null;
  unique_ips: string[];
  countries: string[];
  user_agents: string[];
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // --- CORS headers (allow any origin for pixel requests) ---
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
    };

    // Handle preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: { ...corsHeaders, 'Access-Control-Allow-Headers': '*' },
      });
    }

    // Only GET requests
    if (request.method !== 'GET') {
      return new Response('Method not allowed', { status: 405 });
    }

    // Route: /track — log open event and return pixel
    if (path === '/track' || path === '/track/') {
      return handleTrack(url, request, env, corsHeaders);
    }

    // Route: /stats — return aggregated statistics
    if (path === '/stats' || path === '/stats/') {
      return handleStats(url, env, corsHeaders);
    }

    // Health check
    if (path === '/health' || path === '/') {
      return new Response(JSON.stringify({ status: 'ok', service: 'novamail-tracker' }), {
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    }

    return new Response('Not found', { status: 404, headers: corsHeaders });
  },
} satisfies ExportedHandler<Env>;

/**
 * Handle /track endpoint:
 * 1. Validate parameters
 * 2. Log the open event to R2
 * 3. Return 1x1 transparent GIF
 */
async function handleTrack(url: URL, request: Request, env: Env, cors: Record<string, string>): Promise<Response> {
  const mailIdStr = url.searchParams.get('e') || '';
  const token = url.searchParams.get('t') || '';
  const signature = url.searchParams.get('s') || '';

  // Validate parameters
  const errors: string[] = [];
  if (!MAIL_ID_RE.test(mailIdStr)) errors.push('invalid mail_id (e)');
  if (!TOKEN_RE.test(token)) errors.push('invalid token (t)');

  if (errors.length > 0) {
    // Return pixel anyway — don't reveal that tracking exists to the email client
    return pixelResponse(cors);
  }

  const mailId = parseInt(mailIdStr, 10);

  // HMAC-SHA256 signature verification (M3-10)
  if (env.HMAC_SECRET) {
    if (!signature) {
      return pixelResponse(cors);
    }
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(env.HMAC_SECRET),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const data = encoder.encode(mailIdStr + token);
    const sig = await crypto.subtle.sign('HMAC', key, data);
    const expected = Array.from(new Uint8Array(sig))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    if (signature !== expected) {
      // Forged or tampered — return pixel silently, do NOT log event
      return pixelResponse(cors);
    }
  }

  // Extract client info
  const ip = request.headers.get('CF-Connecting-IP') ||
             request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
             'unknown';
  const country = request.headers.get('CF-IPCountry') || null;
  const userAgent = request.headers.get('User-Agent') || 'unknown';
  const timestamp = Date.now();

  // Build event record
  const event: TrackEvent = { mail_id: mailId, token, ip, country, user_agent, timestamp };
  const line = JSON.stringify(event) + '\n';

  // Append to R2 (fire-and-forget via ctx.waitUntil)
  ctx.waitUntil(
    (async () => {
      try {
        const key = `logs/${mailId}.jsonl`;
        // Read existing content, append new line
        let existing = '';
        try {
          const obj = await env.TRACKER_BUCKET.get(key);
          existing = obj ? await obj.text() : '';
        } catch {
          // File doesn't exist yet
        }
        await env.TRACKER_BUCKET.put(key, existing + line, {
          httpMetadata: { contentType: 'application/jsonl' },
        });
      } catch (err) {
        // Silent failure — pixel response already sent
        console.error('R2 write failed:', err);
      }
    })()
  );

  return pixelResponse(cors);
}

/**
 * Handle /stats endpoint:
 * 1. Validate API token
 * 2. Read R2 logs for the given mail_id
 * 3. Aggregate and return stats as JSON
 */
async function handleStats(url: URL, env: Env, cors: Record<string, string>): Promise<Response> {
  // Authenticate
  const apiToken = url.searchParams.get('api_token') || '';
  if (apiToken !== env.STATS_API_TOKEN) {
    return new Response(JSON.stringify({ error: 'unauthorized' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json', ...cors },
    });
  }

  const mailIdStr = url.searchParams.get('mail_id') || '';
  if (!MAIL_ID_RE.test(mailIdStr)) {
    return new Response(JSON.stringify({ error: 'invalid mail_id' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json', ...cors },
    });
  }

  const mailId = parseInt(mailIdStr, 10);
  const key = `logs/${mailId}.jsonl`;

  let fileContent: string;
  try {
    const obj = await env.TRACKER_BUCKET.get(key);
    if (!obj) {
      return new Response(JSON.stringify({ mail_id: mailId, total_opens: 0 }), {
        headers: { 'Content-Type': 'application/json', ...cors },
      });
    }
    fileContent = await obj.text();
  } catch {
    return new Response(JSON.stringify({ mail_id: mailId, total_opens: 0 }), {
      headers: { 'Content-Type': 'application/json', ...cors },
    });
  }

  // Parse events
  const lines = fileContent.trim().split('\n').filter(Boolean);
  const events: TrackEvent[] = lines.map((l) => {
    try { return JSON.parse(l) as TrackEvent; } catch { return null; }
  }).filter(Boolean) as TrackEvent[];

  if (events.length === 0) {
    return new Response(JSON.stringify({ mail_id: mailId, total_opens: 0 }), {
      headers: { 'Content-Type': 'application/json', ...cors },
    });
  }

  // Aggregate
  const timestamps = events.map((e) => e.timestamp).sort((a, b) => a - b);
  const uniqueIps = [...new Set(events.map((e) => e.ip))];
  const countries = [...new Set(events.map((e) => e.country).filter(Boolean))] as string[];
  const userAgents = [...new Set(events.map((e) => e.user_agent))];

  const stats: StatsResponse = {
    mail_id: mailId,
    total_opens: events.length,
    first_opened_at: timestamps[0] || null,
    last_opened_at: timestamps[timestamps.length - 1] || null,
    unique_ips: uniqueIps,
    countries,
    user_agents: userAgents,
  };

  return new Response(JSON.stringify(stats, null, 2), {
    headers: { 'Content-Type': 'application/json', ...cors },
  });
}

/**
 * Return a 1x1 transparent GIF pixel.
 */
function pixelResponse(cors: Record<string, string>): Response {
  return new Response(PIXEL_BYTES, {
    headers: {
      'Content-Type': 'image/gif',
      'Content-Length': PIXEL_BYTES.length.toString(),
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0',
      ...cors,
    },
  });
}