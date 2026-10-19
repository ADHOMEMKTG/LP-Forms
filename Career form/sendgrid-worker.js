/**
 * Cloudflare Worker: job application → SendGrid email (resume attached)
 *
 * Secrets (Worker → Settings → Variables and Secrets, type "Secret"):
 *   SENDGRID_API_KEY  SendGrid API key with "Mail Send" permission
 *   FROM_EMAIL        A sender verified in SendGrid, e.g. forms@yourdomain.com
 *   TOKEN_SECRET      Any long random string (encrypts client emails)
 *   ADMIN_KEY         Any long random string (protects the /token route)
 *
 * Optional plain variable:
 *   ALLOWED_ORIGINS   Comma-separated sites allowed to post. Exact sites or wildcards:
 *                     *.homecomfort.services,https://homecomfort.services
 *                     (the wildcard covers every https subdomain, e.g. oha.homecomfort.services)
 *                     Leave empty to allow any site.
 *
 * Routes:
 *   POST /        the form posts here (multipart: token, client_name, fields, resume)
 *   POST /token   admin only: { "email": "hr@client.com" } → { "token": "..." }
 */

const MAX_RESUME_BYTES = 5 * 1024 * 1024;
const ALLOWED_EXT = /\.(pdf|docx?)$/i;

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const cors = corsHeaders(origin, env);

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405, cors);

    const url = new URL(request.url);
    try {
      // Admin route: protected by ADMIN_KEY, so it works from PowerShell/curl (no Origin header)
      if (url.pathname === '/token') return await makeToken(request, env, cors);

      // Form route: only accept posts from allowed websites
      if (!cors['Access-Control-Allow-Origin']) return json({ error: 'Origin not allowed' }, 403, cors);
      return await sendApplication(request, env, cors);
    } catch (err) {
      console.error(err);
      return json({ error: 'Server error' }, 500, cors);
    }
  }
};

/* ---------- Admin: create an encrypted token for a client's email ---------- */
async function makeToken(request, env, cors) {
  if (request.headers.get('X-Admin-Key') !== env.ADMIN_KEY) {
    return json({ error: 'Unauthorized' }, 401, cors);
  }
  const { email } = await request.json();
  if (!isEmail(email)) return json({ error: 'Invalid email' }, 400, cors);
  return json({ token: await encrypt(email, env.TOKEN_SECRET) }, 200, cors);
}

/* ---------- Form submission ---------- */
async function sendApplication(request, env, cors) {
  const form = await request.formData();

  let toEmail;
  try {
    toEmail = await decrypt(String(form.get('token') || ''), env.TOKEN_SECRET);
  } catch {
    return json({ error: 'Invalid token' }, 400, cors);
  }
  if (!isEmail(toEmail)) return json({ error: 'Invalid token' }, 400, cors);

  let fields;
  try { fields = JSON.parse(String(form.get('fields') || '{}')); }
  catch { return json({ error: 'Bad fields' }, 400, cors); }

  const clientName = clean(form.get('client_name')) || 'your website';
  const applicant = clean(fields.Name) || 'New applicant';

  // Resume attachment
  const attachments = [];
  const resume = form.get('resume');
  if (resume && typeof resume === 'object' && resume.size > 0) {
    if (resume.size > MAX_RESUME_BYTES) return json({ error: 'Resume too large' }, 413, cors);
    if (!ALLOWED_EXT.test(resume.name)) return json({ error: 'Resume type not allowed' }, 415, cors);
    attachments.push({
      content: toBase64(await resume.arrayBuffer()),
      filename: resume.name.replace(/[^\w.\- ]/g, '_'),
      type: resume.type || 'application/octet-stream',
      disposition: 'attachment'
    });
  }

  // Email body
  const labels = {
    Name: 'Name', Phone: 'Phone #', Email: 'Email', Date_Attending: 'Date Attending',
    Positions: 'Position(s) interested in', Resume_File_Name: 'Resume',
    Message: 'Message', contact_consent: 'Consent'
  };
  const rows = Object.keys(labels).map(k =>
    `<tr><td style="padding:8px 12px;border:1px solid #ddd;background:#f6f6f6;font-weight:600;">${labels[k]}</td>` +
    `<td style="padding:8px 12px;border:1px solid #ddd;">${escapeHtml(clean(fields[k])) || '—'}</td></tr>`
  ).join('');
  const html =
    `<div style="font-family:Arial,sans-serif;font-size:14px;color:#222;">` +
    `<p>New job application from <strong>${escapeHtml(applicant)}</strong> on ${escapeHtml(clientName)}.</p>` +
    `<table style="border-collapse:collapse;">${rows}</table>` +
    `<p style="color:#666;font-size:12px;">Reply to this email to contact the applicant.</p></div>`;
  const text = Object.keys(labels).map(k => `${labels[k]}: ${clean(fields[k])}`).join('\n');

  const payload = {
    personalizations: [{ to: [{ email: toEmail }] }],
    from: { email: env.FROM_EMAIL, name: `${clientName} Careers` },
    subject: `New job application: ${applicant}`,
    content: [{ type: 'text/plain', value: text }, { type: 'text/html', value: html }],
    attachments: attachments.length ? attachments : undefined
  };
  if (isEmail(fields.Email)) payload.reply_to = { email: fields.Email, name: applicant };

  const sg = await fetch('https://api.sendgrid.com/v3/mail/send', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.SENDGRID_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!sg.ok) {
    console.error('SendGrid error', sg.status, await sg.text());
    return json({ error: 'Email failed' }, 502, cors);
  }
  return json({ ok: true }, 200, cors);
}

/* ---------- Encryption (AES-GCM) ---------- */
async function getKey(secret) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(secret));
  return crypto.subtle.importKey('raw', hash, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function encrypt(plain, secret) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await getKey(secret), new TextEncoder().encode(plain));
  const out = new Uint8Array(iv.length + ct.byteLength);
  out.set(iv); out.set(new Uint8Array(ct), iv.length);
  return toBase64(out.buffer).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function decrypt(token, secret) {
  const b64 = token.replace(/-/g, '+').replace(/_/g, '/');
  const bytes = Uint8Array.from(atob(b64 + '==='.slice((b64.length + 3) % 4)), c => c.charCodeAt(0));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12) }, await getKey(secret), bytes.slice(12));
  return new TextDecoder().decode(pt);
}

/* ---------- Helpers ---------- */
function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}
function corsHeaders(origin, env) {
  // Entries can be exact ("https://site.com") or wildcards ("*.homecomfort.services")
  const allowed = (env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  let host = '';
  try { host = new URL(origin).hostname.toLowerCase(); } catch {}
  const isHttps = origin.toLowerCase().startsWith('https://');
  const ok = allowed.length === 0 || allowed.some(rule => {
    if (rule.startsWith('*.')) {
      const base = rule.slice(2);
      return isHttps && (host === base || host.endsWith('.' + base));
    }
    return rule === origin.toLowerCase();
  });
  return {
    'Access-Control-Allow-Origin': ok ? (origin || '*') : '',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Key',
    'Vary': 'Origin'
  };
}
function json(obj, status, headers) {
  return new Response(JSON.stringify(obj), { status, headers: { ...headers, 'Content-Type': 'application/json' } });
}
function clean(v) { return String(v == null ? '' : v).trim().slice(0, 5000); }
function isEmail(v) { return typeof v === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); }
function escapeHtml(s) {
  return s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
