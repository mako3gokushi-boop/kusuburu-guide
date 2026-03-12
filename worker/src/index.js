// kusuburu-api — Cloudflare Worker
// チェックインフォーム送信先 + 管理API + LINE通知

const RATE_LIMIT_MAX = 10;
const RATE_LIMIT_WINDOW = 3600; // 1 hour in seconds
const MAX_PHOTO_SIZE = 5 * 1024 * 1024; // 5MB
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCKOUT_SECONDS = 900; // 15 minutes

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function generateUUID() {
  return crypto.randomUUID();
}

function corsHeaders(origin, allowedOrigin) {
  const allowed = origin === allowedOrigin || origin === 'https://mako3gokushi-boop.github.io';
  return {
    'Access-Control-Allow-Origin': allowed ? origin : allowedOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}

function jsonResponse(data, status = 200, origin = '', allowedOrigin = '') {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(origin, allowedOrigin),
    },
  });
}

// --- Password Hashing (PBKDF2) ---

async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return btoa(String.fromCharCode(...new Uint8Array(bits)));
}

async function verifyPassword(password, salt, hash) {
  const computed = await hashPassword(password, salt);
  // Constant-time comparison
  if (computed.length !== hash.length) return false;
  let result = 0;
  for (let i = 0; i < computed.length; i++) {
    result |= computed.charCodeAt(i) ^ hash.charCodeAt(i);
  }
  return result === 0;
}

// --- Login Attempt Tracking ---

async function checkLoginAttempts(clientIP, env) {
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - LOGIN_LOCKOUT_SECONDS;

  // Clean old entries
  await env.DB.prepare('DELETE FROM login_attempts WHERE timestamp < ?').bind(windowStart).run();

  // Count recent failed attempts
  const count = await env.DB.prepare(
    'SELECT COUNT(*) as cnt FROM login_attempts WHERE ip = ? AND timestamp > ? AND success = 0'
  ).bind(clientIP, windowStart).first();

  return {
    locked: count && count.cnt >= LOGIN_MAX_ATTEMPTS,
    attempts: count ? count.cnt : 0,
    remaining: LOGIN_MAX_ATTEMPTS - (count ? count.cnt : 0),
  };
}

async function recordLoginAttempt(clientIP, success, env) {
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    'INSERT INTO login_attempts (ip, timestamp, success) VALUES (?, ?, ?)'
  ).bind(clientIP, now, success ? 1 : 0).run();
}

// --- Suspicious Access LINE Notification ---

async function sendSecurityAlert(env, alertType, details) {
  const token = env.LINE_CHANNEL_TOKEN;
  const userId = env.LINE_USER_ID;
  if (!token || !userId) return;

  const alerts = {
    rate_limit: `⚠️ レート制限超過\nIP: ${details.ip}`,
    honeypot: `🤖 ボット検知（ハニーポット）\nIP: ${details.ip}`,
    login_lockout: `🔒 ログイン5回失敗 — アカウントロック\nIP: ${details.ip}`,
  };

  const message = alerts[alertType] || `⚠️ 不審アクセス: ${alertType}`;

  try {
    await fetch('https://api.line.me/v2/bot/message/push', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({
        to: userId,
        messages: [{ type: 'text', text: message }],
      }),
    });
  } catch (e) {
    console.error('Security alert LINE notification failed:', e);
  }
}

// --- Auth ---

async function verifyAdmin(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return false;
  const token = authHeader.slice(7);

  // Check session tokens in admin_tokens table
  const result = await env.DB.prepare('SELECT token FROM admin_tokens WHERE token = ?').bind(token).first();
  return !!result;
}

async function handleLogin(request, env, origin) {
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';

  // Check if IP is locked out
  const loginStatus = await checkLoginAttempts(clientIP, env);
  if (loginStatus.locked) {
    // Send LINE alert on lockout
    sendSecurityAlert(env, 'login_lockout', { ip: clientIP });
    return jsonResponse({
      error: 'Too many login attempts. Please wait 15 minutes.',
      locked: true,
      lockout_minutes: 15,
    }, 429, origin, env.ALLOWED_ORIGIN);
  }

  let data;
  try {
    data = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400, origin, env.ALLOWED_ORIGIN);
  }

  const password = data.password;
  if (!password || typeof password !== 'string') {
    return jsonResponse({ error: 'Password required' }, 400, origin, env.ALLOWED_ORIGIN);
  }

  // Check if custom password is set in D1
  const customPw = await env.DB.prepare('SELECT password_hash, salt FROM admin_passwords ORDER BY id DESC LIMIT 1').first();

  let authenticated = false;
  let needsPasswordChange = false;

  if (customPw) {
    // Verify against hashed password
    authenticated = await verifyPassword(password, customPw.salt, customPw.password_hash);
  } else {
    // Fall back to ADMIN_TOKEN env var (initial "0000" password)
    const adminToken = env.ADMIN_TOKEN;
    authenticated = adminToken && password === adminToken;
    if (authenticated) {
      needsPasswordChange = true;
    }
  }

  if (!authenticated) {
    await recordLoginAttempt(clientIP, false, env);
    const remaining = loginStatus.remaining - 1;
    return jsonResponse({
      error: 'Invalid password',
      remaining_attempts: Math.max(0, remaining),
    }, 401, origin, env.ALLOWED_ORIGIN);
  }

  // Record successful login
  await recordLoginAttempt(clientIP, true, env);

  // Clear failed attempts for this IP on success
  await env.DB.prepare(
    'DELETE FROM login_attempts WHERE ip = ? AND success = 0'
  ).bind(clientIP).run();

  // Generate session token
  const sessionToken = generateUUID();
  await env.DB.prepare(
    'INSERT INTO admin_tokens (token, created_at) VALUES (?, datetime(\'now\'))'
  ).bind(sessionToken).run();

  return jsonResponse({
    success: true,
    token: sessionToken,
    needs_password_change: needsPasswordChange,
  }, 200, origin, env.ALLOWED_ORIGIN);
}

async function handleChangePassword(request, env, origin) {
  if (!await verifyAdmin(request, env)) {
    return jsonResponse({ error: 'Unauthorized' }, 401, origin, env.ALLOWED_ORIGIN);
  }

  let data;
  try {
    data = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400, origin, env.ALLOWED_ORIGIN);
  }

  const newPassword = data.new_password;
  if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 4) {
    return jsonResponse({ error: 'Password must be at least 4 characters' }, 400, origin, env.ALLOWED_ORIGIN);
  }

  // Generate salt and hash
  const salt = generateUUID();
  const hash = await hashPassword(newPassword, salt);

  // Delete old password records and insert new
  await env.DB.prepare('DELETE FROM admin_passwords').run();
  await env.DB.prepare(
    'INSERT INTO admin_passwords (password_hash, salt) VALUES (?, ?)'
  ).bind(hash, salt).run();

  return jsonResponse({ success: true }, 200, origin, env.ALLOWED_ORIGIN);
}

// --- Turnstile Verification ---

async function verifyTurnstile(token, clientIP, env) {
  const secretKey = env.TURNSTILE_SECRET_KEY;
  if (!secretKey) return true; // Skip if not configured

  try {
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        secret: secretKey,
        response: token,
        remoteip: clientIP,
      }),
    });
    const result = await res.json();
    return result.success === true;
  } catch (e) {
    console.error('Turnstile verification failed:', e);
    return true; // Fail open if Turnstile is unreachable
  }
}

async function checkRateLimit(clientIP, env) {
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - RATE_LIMIT_WINDOW;

  // Clean old entries
  await env.DB.prepare('DELETE FROM rate_limits WHERE timestamp < ?').bind(windowStart).run();

  // Count recent requests
  const count = await env.DB.prepare(
    'SELECT COUNT(*) as cnt FROM rate_limits WHERE ip = ? AND timestamp > ?'
  ).bind(clientIP, windowStart).first();

  if (count && count.cnt >= RATE_LIMIT_MAX) return false;

  // Add new entry
  await env.DB.prepare('INSERT INTO rate_limits (ip, timestamp) VALUES (?, ?)').bind(clientIP, now).run();
  return true;
}

async function sendLineNotification(env, checkinData) {
  const token = env.LINE_CHANNEL_TOKEN;
  const userId = env.LINE_USER_ID;
  if (!token || !userId) return;

  const name = escapeHtml(checkinData.name);
  const adults = checkinData.adults || 0;
  const children = checkinData.children || 0;
  const checkinDate = checkinData.checkin_date || '';
  const checkoutDate = checkinData.checkout_date || '';

  const message = `🏠 新しいチェックイン\n${name}様\n大人${adults}名・子供${children}名\n${checkinDate}〜${checkoutDate}`;

  try {
    await fetch('https://api.line.me/v2/bot/message/push', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({
        to: userId,
        messages: [{ type: 'text', text: message }],
      }),
    });
  } catch (e) {
    console.error('LINE notification failed:', e);
  }
}

// --- Route Handlers ---

async function handleCheckin(request, env, origin) {
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
  const allowed = await checkRateLimit(clientIP, env);
  if (!allowed) {
    sendSecurityAlert(env, 'rate_limit', { ip: clientIP });
    return jsonResponse({ error: 'Rate limit exceeded. Try again later.' }, 429, origin, env.ALLOWED_ORIGIN);
  }

  let data;
  try {
    data = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400, origin, env.ALLOWED_ORIGIN);
  }

  // Honeypot check (bot trap)
  if (data.website || data.url || data.company_url) {
    sendSecurityAlert(env, 'honeypot', { ip: clientIP });
    return jsonResponse({ success: true, id: 'ok' }, 201, origin, env.ALLOWED_ORIGIN);
  }

  // Turnstile CAPTCHA verification
  if (data.cf_turnstile_response) {
    const turnstileValid = await verifyTurnstile(data.cf_turnstile_response, clientIP, env);
    if (!turnstileValid) {
      return jsonResponse({ error: 'CAPTCHA verification failed' }, 403, origin, env.ALLOWED_ORIGIN);
    }
  } else if (env.TURNSTILE_SECRET_KEY) {
    // Turnstile is configured but no token provided
    return jsonResponse({ error: 'CAPTCHA token required' }, 400, origin, env.ALLOWED_ORIGIN);
  }

  // Validate required fields
  if (!data.name || !data.phone || !data.checkin_date || !data.checkout_date) {
    return jsonResponse({ error: 'Missing required fields: name, phone, checkin_date, checkout_date' }, 400, origin, env.ALLOWED_ORIGIN);
  }

  // Input validation
  if (typeof data.name !== 'string' || data.name.length < 1 || data.name.length > 100) {
    return jsonResponse({ error: 'Invalid name' }, 400, origin, env.ALLOWED_ORIGIN);
  }
  if (typeof data.phone !== 'string' || data.phone.length < 3 || data.phone.length > 20) {
    return jsonResponse({ error: 'Invalid phone' }, 400, origin, env.ALLOWED_ORIGIN);
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(data.checkin_date) || !/^\d{4}-\d{2}-\d{2}$/.test(data.checkout_date)) {
    return jsonResponse({ error: 'Invalid date format (YYYY-MM-DD)' }, 400, origin, env.ALLOWED_ORIGIN);
  }
  if (data.checkin_date > data.checkout_date) {
    return jsonResponse({ error: 'checkout_date must be after checkin_date' }, 400, origin, env.ALLOWED_ORIGIN);
  }
  const adults = parseInt(data.adults) || 1;
  const children = parseInt(data.children) || 0;
  if (adults < 1 || adults > 20 || children < 0 || children > 20) {
    return jsonResponse({ error: 'Invalid guest count' }, 400, origin, env.ALLOWED_ORIGIN);
  }

  const id = generateUUID();

  await env.DB.prepare(`
    INSERT INTO checkins (id, name, furigana, adults, children, checkin_date, checkout_date, phone, email, zipcode, address, is_foreign, nationality, passport_no, transport, allergies, notes, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
  `).bind(
    id,
    data.name,
    data.furigana || '',
    adults,
    children,
    data.checkin_date,
    data.checkout_date,
    data.phone,
    data.email || '',
    data.zipcode || '',
    data.address || '',
    data.is_foreign ? 1 : 0,
    data.nationality || '',
    data.passport_no || '',
    data.transport || '',
    data.allergies || '',
    data.notes || ''
  ).run();

  // Send LINE notification (fire and forget)
  sendLineNotification(env, { ...data, id });

  return jsonResponse({ success: true, id }, 201, origin, env.ALLOWED_ORIGIN);
}

async function handlePhotoUpload(request, env, origin) {
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
  const allowed = await checkRateLimit(clientIP, env);
  if (!allowed) {
    return jsonResponse({ error: 'Rate limit exceeded' }, 429, origin, env.ALLOWED_ORIGIN);
  }

  const contentType = request.headers.get('Content-Type') || '';
  let photoData, checkinId;

  if (contentType.includes('application/json')) {
    const data = await request.json();
    photoData = data.photo; // base64 string
    checkinId = data.checkin_id;
  } else {
    return jsonResponse({ error: 'Content-Type must be application/json' }, 400, origin, env.ALLOWED_ORIGIN);
  }

  if (!checkinId || !photoData) {
    return jsonResponse({ error: 'Missing checkin_id or photo' }, 400, origin, env.ALLOWED_ORIGIN);
  }

  // Check size (base64 is ~33% larger than binary)
  if (photoData.length > MAX_PHOTO_SIZE * 1.34) {
    return jsonResponse({ error: 'Photo too large. Max 5MB.' }, 413, origin, env.ALLOWED_ORIGIN);
  }

  // Validate it looks like a base64 image
  if (!photoData.startsWith('data:image/jpeg') && !photoData.startsWith('data:image/png')) {
    return jsonResponse({ error: 'Only JPEG/PNG allowed' }, 400, origin, env.ALLOWED_ORIGIN);
  }

  // Store in D1 (since R2 is not enabled)
  await env.DB.prepare('UPDATE checkins SET passport_photo = ? WHERE id = ?')
    .bind(photoData, checkinId).run();

  return jsonResponse({ success: true }, 200, origin, env.ALLOWED_ORIGIN);
}

async function handleAdminCheckins(request, env, origin) {
  if (!await verifyAdmin(request, env)) {
    return jsonResponse({ error: 'Unauthorized' }, 401, origin, env.ALLOWED_ORIGIN);
  }

  const url = new URL(request.url);
  const status = url.searchParams.get('status');
  const search = url.searchParams.get('search');
  const dateFrom = url.searchParams.get('date_from');
  const dateTo = url.searchParams.get('date_to');

  let query = 'SELECT id, name, furigana, adults, children, checkin_date, checkout_date, phone, email, address, is_foreign, nationality, transport, status, created_at FROM checkins WHERE 1=1';
  const params = [];

  if (status) {
    query += ' AND status = ?';
    params.push(status);
  }
  if (search) {
    query += ' AND (name LIKE ? OR furigana LIKE ? OR phone LIKE ?)';
    const s = `%${search}%`;
    params.push(s, s, s);
  }
  if (dateFrom) {
    query += ' AND checkin_date >= ?';
    params.push(dateFrom);
  }
  if (dateTo) {
    query += ' AND checkin_date <= ?';
    params.push(dateTo);
  }

  query += ' ORDER BY created_at DESC';

  const stmt = env.DB.prepare(query);
  const result = params.length > 0 ? await stmt.bind(...params).all() : await stmt.all();

  return jsonResponse({ checkins: result.results }, 200, origin, env.ALLOWED_ORIGIN);
}

async function handleAdminCheckinDetail(env, id, request, origin) {
  if (!await verifyAdmin(request, env)) {
    return jsonResponse({ error: 'Unauthorized' }, 401, origin, env.ALLOWED_ORIGIN);
  }

  const checkin = await env.DB.prepare(
    'SELECT id, name, furigana, adults, children, checkin_date, checkout_date, phone, email, zipcode, address, is_foreign, nationality, passport_no, transport, allergies, notes, status, created_at FROM checkins WHERE id = ?'
  ).bind(id).first();

  if (!checkin) {
    return jsonResponse({ error: 'Not found' }, 404, origin, env.ALLOWED_ORIGIN);
  }

  return jsonResponse({ checkin }, 200, origin, env.ALLOWED_ORIGIN);
}

async function handleAdminPhoto(env, id, request, origin) {
  if (!await verifyAdmin(request, env)) {
    return jsonResponse({ error: 'Unauthorized' }, 401, origin, env.ALLOWED_ORIGIN);
  }

  const result = await env.DB.prepare('SELECT passport_photo FROM checkins WHERE id = ?').bind(id).first();
  if (!result || !result.passport_photo) {
    return jsonResponse({ error: 'No photo found' }, 404, origin, env.ALLOWED_ORIGIN);
  }

  return jsonResponse({ photo: result.passport_photo }, 200, origin, env.ALLOWED_ORIGIN);
}

async function handleAdminDelete(env, id, request, origin) {
  if (!await verifyAdmin(request, env)) {
    return jsonResponse({ error: 'Unauthorized' }, 401, origin, env.ALLOWED_ORIGIN);
  }

  await env.DB.prepare('DELETE FROM checkins WHERE id = ?').bind(id).run();
  return jsonResponse({ success: true }, 200, origin, env.ALLOWED_ORIGIN);
}

async function handleAdminUpdate(env, id, request, origin) {
  if (!await verifyAdmin(request, env)) {
    return jsonResponse({ error: 'Unauthorized' }, 401, origin, env.ALLOWED_ORIGIN);
  }

  const data = await request.json();
  const updates = [];
  const params = [];

  // Status update
  if (data.status) {
    const validStatuses = ['pending', 'checked_in', 'checked_out'];
    if (!validStatuses.includes(data.status)) {
      return jsonResponse({ error: 'Invalid status' }, 400, origin, env.ALLOWED_ORIGIN);
    }
    updates.push('status = ?');
    params.push(data.status);
  }

  // Checkout date update (for extending stay)
  if (data.checkout_date) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(data.checkout_date)) {
      return jsonResponse({ error: 'Invalid date format (YYYY-MM-DD)' }, 400, origin, env.ALLOWED_ORIGIN);
    }
    updates.push('checkout_date = ?');
    params.push(data.checkout_date);
  }

  if (updates.length === 0) {
    return jsonResponse({ error: 'No valid fields to update' }, 400, origin, env.ALLOWED_ORIGIN);
  }

  params.push(id);
  await env.DB.prepare(`UPDATE checkins SET ${updates.join(', ')} WHERE id = ?`).bind(...params).run();
  return jsonResponse({ success: true }, 200, origin, env.ALLOWED_ORIGIN);
}

async function handleAdminCsvExport(request, env, origin) {
  if (!await verifyAdmin(request, env)) {
    return jsonResponse({ error: 'Unauthorized' }, 401, origin, env.ALLOWED_ORIGIN);
  }

  const result = await env.DB.prepare(
    'SELECT name, furigana, adults, children, checkin_date, checkout_date, phone, email, zipcode, address, is_foreign, nationality, passport_no, transport, allergies, notes, status, created_at FROM checkins ORDER BY created_at DESC'
  ).all();

  const headers = ['氏名', 'フリガナ', '大人', '子供', 'チェックイン', 'チェックアウト', '電話番号', 'メール', '郵便番号', '住所', '外国籍', '国籍', 'パスポート番号', '交通手段', 'アレルギー', '備考', 'ステータス', '登録日時'];
  const csvRows = [headers.join(',')];

  for (const row of result.results) {
    const csvRow = [
      row.name, row.furigana, row.adults, row.children,
      row.checkin_date, row.checkout_date, row.phone, row.email,
      row.zipcode, row.address, row.is_foreign ? 'はい' : 'いいえ',
      row.nationality, row.passport_no, row.transport,
      row.allergies, row.notes, row.status, row.created_at
    ].map(v => `"${String(v || '').replace(/"/g, '""')}"`);
    csvRows.push(csvRow.join(','));
  }

  const csv = '\uFEFF' + csvRows.join('\n'); // BOM for Excel

  return new Response(csv, {
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="checkins.csv"',
      ...corsHeaders(origin, env.ALLOWED_ORIGIN),
    },
  });
}

async function handleAdminStats(request, env, origin) {
  if (!await verifyAdmin(request, env)) {
    return jsonResponse({ error: 'Unauthorized' }, 401, origin, env.ALLOWED_ORIGIN);
  }

  const url = new URL(request.url);
  const from = url.searchParams.get('from') || '';
  const to = url.searchParams.get('to') || '';

  let dateFilter = '';
  const dateParams = [];
  if (from) { dateFilter += " AND strftime('%Y-%m', checkin_date) >= ?"; dateParams.push(from); }
  if (to) { dateFilter += " AND strftime('%Y-%m', checkin_date) <= ?"; dateParams.push(to); }

  const monthlyStmt = env.DB.prepare(
    "SELECT strftime('%Y-%m', checkin_date) as month, COUNT(*) as count FROM checkins WHERE 1=1" + dateFilter + " GROUP BY month ORDER BY month DESC LIMIT 24"
  );
  const nationalityStmt = env.DB.prepare(
    "SELECT nationality, COUNT(*) as count FROM checkins WHERE is_foreign = 1 AND nationality != ''" + dateFilter + " GROUP BY nationality ORDER BY count DESC"
  );
  const avgStmt = env.DB.prepare(
    "SELECT AVG(julianday(checkout_date) - julianday(checkin_date)) as avg_stay FROM checkins WHERE checkout_date IS NOT NULL AND checkin_date IS NOT NULL" + dateFilter
  );
  const totalStmt = env.DB.prepare(
    "SELECT COUNT(*) as total FROM checkins WHERE 1=1" + dateFilter
  );
  const weekdayStmt = env.DB.prepare(
    "SELECT CAST(strftime('%w', checkin_date) AS INTEGER) as dow, COUNT(*) as count FROM checkins WHERE 1=1" + dateFilter + " GROUP BY dow ORDER BY dow"
  );
  const repeaterStmt = env.DB.prepare(
    "SELECT name, COUNT(*) as visits FROM checkins WHERE 1=1" + dateFilter + " GROUP BY name HAVING visits > 1 ORDER BY visits DESC LIMIT 20"
  );

  const bind = (stmt) => dateParams.length > 0 ? stmt.bind(...dateParams) : stmt;

  const [monthlyResult, nationalityResult, avgResult, totalResult, weekdayResult, repeaterResult] = await Promise.all([
    bind(monthlyStmt).all(),
    bind(nationalityStmt).all(),
    bind(avgStmt).first(),
    bind(totalStmt).first(),
    bind(weekdayStmt).all(),
    bind(repeaterStmt).all(),
  ]);

  return jsonResponse({
    monthly: monthlyResult.results || [],
    nationalities: nationalityResult.results || [],
    avg_stay: avgResult ? Math.round((avgResult.avg_stay || 0) * 10) / 10 : 0,
    total: totalResult ? totalResult.total : 0,
    weekday: weekdayResult.results || [],
    repeaters: repeaterResult.results || [],
  }, 200, origin, env.ALLOWED_ORIGIN);
}

async function handleAdminStatsMonthly(request, env, origin, month) {
  if (!await verifyAdmin(request, env)) {
    return jsonResponse({ error: 'Unauthorized' }, 401, origin, env.ALLOWED_ORIGIN);
  }

  if (!/^\d{4}-\d{2}$/.test(month)) {
    return jsonResponse({ error: 'Invalid month format (YYYY-MM)' }, 400, origin, env.ALLOWED_ORIGIN);
  }

  const result = await env.DB.prepare(
    "SELECT id, name, furigana, adults, children, checkin_date, checkout_date, phone, status, created_at FROM checkins WHERE strftime('%Y-%m', checkin_date) = ? ORDER BY checkin_date"
  ).bind(month).all();

  return jsonResponse({ month, checkins: result.results || [] }, 200, origin, env.ALLOWED_ORIGIN);
}

// --- Main Router ---

export default {
  async scheduled(event, env, ctx) {
    // Auto-checkout: JST 06:00 daily (UTC 21:00)
    const today = new Date().toISOString().split('T')[0];
    const result = await env.DB.prepare(
      "UPDATE checkins SET status = 'checked_out' WHERE checkout_date < ? AND status = 'checked_in'"
    ).bind(today).run();
    console.log(`Auto-checkout: ${result.meta.changes} records updated`);
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const origin = request.headers.get('Origin') || '';

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(origin, env.ALLOWED_ORIGIN),
      });
    }

    try {
      // Public endpoints
      if (path === '/checkin' && method === 'POST') {
        return handleCheckin(request, env, origin);
      }
      if (path === '/checkin/photo' && method === 'POST') {
        return handlePhotoUpload(request, env, origin);
      }

      // Auth endpoints
      if (path === '/admin/login' && method === 'POST') {
        return handleLogin(request, env, origin);
      }
      if (path === '/admin/change-password' && method === 'POST') {
        return handleChangePassword(request, env, origin);
      }

      // Admin endpoints
      if (path === '/admin/checkins' && method === 'GET') {
        return handleAdminCheckins(request, env, origin);
      }
      if (path === '/admin/stats' && method === 'GET') {
        return handleAdminStats(request, env, origin);
      }
      const monthlyMatch = path.match(/^\/admin\/stats\/monthly\/(\d{4}-\d{2})$/);
      if (monthlyMatch && method === 'GET') {
        return handleAdminStatsMonthly(request, env, origin, monthlyMatch[1]);
      }
      if (path === '/admin/checkins/csv' && method === 'GET') {
        return handleAdminCsvExport(request, env, origin);
      }

      const checkinMatch = path.match(/^\/admin\/checkins\/([a-f0-9-]+)$/);
      if (checkinMatch) {
        const id = checkinMatch[1];
        if (method === 'GET') return handleAdminCheckinDetail(env, id, request, origin);
        if (method === 'DELETE') return handleAdminDelete(env, id, request, origin);
        if (method === 'PUT') return handleAdminUpdate(env, id, request, origin);
      }

      const photoMatch = path.match(/^\/admin\/photo\/([a-f0-9-]+)$/);
      if (photoMatch && method === 'GET') {
        return handleAdminPhoto(env, photoMatch[1], request, origin);
      }

      return jsonResponse({ error: 'Not found' }, 404, origin, env.ALLOWED_ORIGIN);
    } catch (e) {
      console.error('Error:', e);
      return jsonResponse({ error: 'Internal server error' }, 500, origin, env.ALLOWED_ORIGIN);
    }
  },
};
