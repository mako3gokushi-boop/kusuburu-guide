// kusuburu-api — Cloudflare Worker
// チェックインフォーム送信先 + 管理API + LINE通知

const RATE_LIMIT_MAX = 10;
const RATE_LIMIT_WINDOW = 3600; // 1 hour in seconds
const MAX_PHOTO_SIZE = 5 * 1024 * 1024; // 5MB

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

async function verifyAdmin(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return false;
  const token = authHeader.slice(7);
  const adminToken = env.ADMIN_TOKEN;
  if (adminToken && token === adminToken) return true;
  const result = await env.DB.prepare('SELECT token FROM admin_tokens WHERE token = ?').bind(token).first();
  return !!result;
}

async function checkRateLimit(clientIP, env) {
  const key = `ratelimit:${clientIP}`;
  // Use D1 for simple rate limiting
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
    return jsonResponse({ error: 'Rate limit exceeded. Try again later.' }, 429, origin, env.ALLOWED_ORIGIN);
  }

  let data;
  try {
    data = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400, origin, env.ALLOWED_ORIGIN);
  }

  // Validate required fields
  if (!data.name || !data.phone || !data.checkin_date || !data.checkout_date) {
    return jsonResponse({ error: 'Missing required fields: name, phone, checkin_date, checkout_date' }, 400, origin, env.ALLOWED_ORIGIN);
  }

  const id = generateUUID();

  await env.DB.prepare(`
    INSERT INTO checkins (id, name, furigana, adults, children, checkin_date, checkout_date, phone, email, zipcode, address, is_foreign, nationality, passport_no, transport, allergies, notes, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
  `).bind(
    id,
    data.name,
    data.furigana || '',
    data.adults || 1,
    data.children || 0,
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

  const [monthlyResult, nationalityResult, avgResult, totalResult] = await Promise.all([
    env.DB.prepare(
      "SELECT strftime('%Y-%m', checkin_date) as month, COUNT(*) as count FROM checkins GROUP BY month ORDER BY month DESC LIMIT 12"
    ).all(),
    env.DB.prepare(
      "SELECT nationality, COUNT(*) as count FROM checkins WHERE is_foreign = 1 AND nationality != '' GROUP BY nationality ORDER BY count DESC"
    ).all(),
    env.DB.prepare(
      "SELECT AVG(julianday(checkout_date) - julianday(checkin_date)) as avg_stay FROM checkins WHERE checkout_date IS NOT NULL AND checkin_date IS NOT NULL"
    ).first(),
    env.DB.prepare("SELECT COUNT(*) as total FROM checkins").first(),
  ]);

  return jsonResponse({
    monthly: monthlyResult.results || [],
    nationalities: nationalityResult.results || [],
    avg_stay: avgResult ? Math.round((avgResult.avg_stay || 0) * 10) / 10 : 0,
    total: totalResult ? totalResult.total : 0,
  }, 200, origin, env.ALLOWED_ORIGIN);
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

      // Admin endpoints
      if (path === '/admin/checkins' && method === 'GET') {
        return handleAdminCheckins(request, env, origin);
      }
      if (path === '/admin/stats' && method === 'GET') {
        return handleAdminStats(request, env, origin);
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
