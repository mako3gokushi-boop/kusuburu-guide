// kusuburu-api — Cloudflare Worker
// チェックインフォーム送信先 + 管理API + LINE通知

const RATE_LIMIT_MAX = 10;
const RATE_LIMIT_WINDOW = 3600; // 1 hour in seconds
const MAX_PHOTO_SIZE = 5 * 1024 * 1024; // 5MB
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCKOUT_SECONDS = 900; // 15 minutes
const PHOTO_RETENTION_DAYS = 30; // days after checkout to keep passport photos
const DATA_RETENTION_YEARS = 3; // years after checkout to keep personal data (旅館業法)

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
  // デモ環境（ALLOWED_ORIGIN="*"）はリクエスト元をそのままエコーバック
  // ワイルドカードはAuthorization付きリクエストで使えないため
  if (allowedOrigin === '*') {
    return {
      'Access-Control-Allow-Origin': origin || '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Max-Age': '86400',
    };
  }
  const allowed = origin === allowedOrigin || origin === 'https://mako3gokushi-boop.github.io';
  return {
    'Access-Control-Allow-Origin': allowed ? origin : allowedOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}

function securityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  };
}

function jsonResponse(data, status = 200, origin = '', allowedOrigin = '') {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(origin, allowedOrigin),
      ...securityHeaders(),
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

// --- AES-256-GCM Encryption ---

async function getEncryptionKey(env) {
  const keyStr = env.ENCRYPTION_KEY;
  if (!keyStr) return null;
  const saltStr = env.ENCRYPTION_SALT;
  if (!saltStr) return null;
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(keyStr), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode(saltStr), iterations: 100000, hash: 'SHA-256' },
    keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function encryptField(plaintext, env) {
  if (!plaintext) return plaintext;
  const key = await getEncryptionKey(env);
  if (!key) return plaintext; // Encryption keys not configured — store as plaintext
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, enc.encode(plaintext)
  );
  // Format: base64(iv):base64(ciphertext)
  const ivB64 = btoa(String.fromCharCode(...iv));
  const ctB64 = btoa(String.fromCharCode(...new Uint8Array(encrypted)));
  return `ENC:${ivB64}:${ctB64}`;
}

async function decryptField(ciphertext, env) {
  if (!ciphertext || !ciphertext.startsWith('ENC:')) return ciphertext;
  const key = await getEncryptionKey(env);
  if (!key) return ciphertext;
  try {
    const parts = ciphertext.slice(4).split(':');
    if (parts.length !== 2) return ciphertext;
    const iv = Uint8Array.from(atob(parts[0]), c => c.charCodeAt(0));
    const ct = Uint8Array.from(atob(parts[1]), c => c.charCodeAt(0));
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv }, key, ct
    );
    return new TextDecoder().decode(decrypted);
  } catch (e) {
    console.error('Decryption failed:', e);
    return '[decryption error]';
  }
}

async function encryptSensitiveFields(data, env) {
  return {
    name: await encryptField(data.name, env),
    phone: await encryptField(data.phone, env),
    passport_no: await encryptField(data.passport_no, env),
  };
}

async function decryptCheckin(checkin, env) {
  if (!checkin) return checkin;
  checkin.name = await decryptField(checkin.name, env);
  checkin.phone = await decryptField(checkin.phone, env);
  checkin.passport_no = await decryptField(checkin.passport_no, env);
  return checkin;
}

async function decryptCheckins(checkins, env) {
  return Promise.all(checkins.map(c => decryptCheckin({ ...c }, env)));
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
  if (!secretKey) return false; // Fail closed if not configured

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
    return false; // Fail closed if Turnstile is unreachable
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

  // Encrypt sensitive fields
  let encrypted;
  try {
    encrypted = await encryptSensitiveFields({
      name: data.name,
      phone: data.phone,
      passport_no: data.passport_no || '',
    }, env);
  } catch (e) {
    if (e.message === 'ENCRYPTION_NOT_CONFIGURED') {
      return jsonResponse({ error: 'Service temporarily unavailable' }, 503, origin, env.ALLOWED_ORIGIN);
    }
    throw e;
  }

  await env.DB.prepare(`
    INSERT INTO checkins (id, name, furigana, adults, children, checkin_date, checkout_date, phone, email, zipcode, address, is_foreign, nationality, passport_no, transport, allergies, notes, receipt_name, age, booking_site, sns_consent, photo_consent, companion_relation, migration_interest, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
  `).bind(
    id,
    encrypted.name,
    data.furigana || '',
    adults,
    children,
    data.checkin_date,
    data.checkout_date,
    encrypted.phone,
    data.email || '',
    data.zipcode || '',
    data.address || '',
    data.is_foreign ? 1 : 0,
    data.nationality || '',
    encrypted.passport_no,
    data.transport || '',
    data.allergies || '',
    data.notes || '',
    data.receipt_name || '',
    parseInt(data.age) || 0,
    data.booking_site || '',
    data.sns_consent || '',
    data.photo_consent || '',
    data.companion_relation || '',
    data.migration_interest || ''
  ).run();

  // Send LINE notification (fire and forget)
  sendLineNotification(env, { ...data, id });

  // Generate one-time photo upload token (valid for 5 minutes)
  let photoUploadToken = null;
  if (data.is_foreign) {
    photoUploadToken = generateUUID();
    const expiresAt = Math.floor(Date.now() / 1000) + 300; // 5 minutes
    await env.DB.prepare(
      'INSERT INTO photo_tokens (token, checkin_id, expires_at) VALUES (?, ?, ?)'
    ).bind(photoUploadToken, id, expiresAt).run();
  }

  return jsonResponse({ success: true, id, photo_upload_token: photoUploadToken }, 201, origin, env.ALLOWED_ORIGIN);
}

async function handlePhotoUpload(request, env, origin) {
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
  const allowed = await checkRateLimit(clientIP, env);
  if (!allowed) {
    return jsonResponse({ error: 'Rate limit exceeded' }, 429, origin, env.ALLOWED_ORIGIN);
  }

  const contentType = request.headers.get('Content-Type') || '';
  let photoData, checkinId, uploadToken;

  if (contentType.includes('application/json')) {
    const data = await request.json();
    photoData = data.photo; // base64 string
    checkinId = data.checkin_id;
    uploadToken = data.photo_upload_token;
  } else {
    return jsonResponse({ error: 'Content-Type must be application/json' }, 400, origin, env.ALLOWED_ORIGIN);
  }

  if (!checkinId || !photoData) {
    return jsonResponse({ error: 'Missing checkin_id or photo' }, 400, origin, env.ALLOWED_ORIGIN);
  }

  // Verify one-time photo upload token
  if (!uploadToken) {
    return jsonResponse({ error: 'Photo upload token required' }, 401, origin, env.ALLOWED_ORIGIN);
  }
  const now = Math.floor(Date.now() / 1000);
  const tokenRecord = await env.DB.prepare(
    'SELECT token, checkin_id, expires_at FROM photo_tokens WHERE token = ?'
  ).bind(uploadToken).first();
  if (!tokenRecord || tokenRecord.checkin_id !== checkinId || tokenRecord.expires_at < now) {
    return jsonResponse({ error: 'Invalid or expired upload token' }, 401, origin, env.ALLOWED_ORIGIN);
  }
  // Delete the token (one-time use)
  await env.DB.prepare('DELETE FROM photo_tokens WHERE token = ?').bind(uploadToken).run();

  // Check size (base64 is ~33% larger than binary)
  if (photoData.length > MAX_PHOTO_SIZE * 1.34) {
    return jsonResponse({ error: 'Photo too large. Max 5MB.' }, 413, origin, env.ALLOWED_ORIGIN);
  }

  // Validate it looks like a base64 image
  if (!photoData.startsWith('data:image/jpeg') && !photoData.startsWith('data:image/png')) {
    return jsonResponse({ error: 'Only JPEG/PNG allowed' }, 400, origin, env.ALLOWED_ORIGIN);
  }

  // Store in R2 if available, otherwise D1 fallback
  if (env.PHOTOS) {
    // Extract binary from base64 data URL
    const base64Part = photoData.split(',')[1];
    const binaryStr = atob(base64Part);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) {
      bytes[i] = binaryStr.charCodeAt(i);
    }
    const contentType = photoData.startsWith('data:image/png') ? 'image/png' : 'image/jpeg';
    const ext = contentType === 'image/png' ? 'png' : 'jpg';
    const r2Key = `passport/${checkinId}.${ext}`;

    await env.PHOTOS.put(r2Key, bytes, {
      httpMetadata: { contentType },
      customMetadata: { checkinId },
    });

    // Store R2 key reference in D1 (not the photo data itself)
    await env.DB.prepare('UPDATE checkins SET passport_photo = ? WHERE id = ?')
      .bind(`r2:${r2Key}`, checkinId).run();
  } else {
    // D1 fallback (legacy)
    await env.DB.prepare('UPDATE checkins SET passport_photo = ? WHERE id = ?')
      .bind(photoData, checkinId).run();
  }

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

  let query = 'SELECT id, name, furigana, adults, children, checkin_date, checkout_date, phone, email, address, is_foreign, nationality, transport, status, admin_memo, receipt_name, age, booking_site, sns_consent, photo_consent, companion_relation, migration_interest, created_at FROM checkins WHERE 1=1';
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

  // Decrypt sensitive fields
  const decrypted = await decryptCheckins(result.results || [], env);
  return jsonResponse({ checkins: decrypted }, 200, origin, env.ALLOWED_ORIGIN);
}

async function handleAdminCheckinDetail(env, id, request, origin) {
  if (!await verifyAdmin(request, env)) {
    return jsonResponse({ error: 'Unauthorized' }, 401, origin, env.ALLOWED_ORIGIN);
  }

  const checkin = await env.DB.prepare(
    'SELECT id, name, furigana, adults, children, checkin_date, checkout_date, phone, email, zipcode, address, is_foreign, nationality, passport_no, transport, allergies, notes, status, admin_memo, receipt_name, age, booking_site, sns_consent, photo_consent, companion_relation, migration_interest, created_at FROM checkins WHERE id = ?'
  ).bind(id).first();

  if (!checkin) {
    return jsonResponse({ error: 'Not found' }, 404, origin, env.ALLOWED_ORIGIN);
  }

  // Decrypt sensitive fields
  const decrypted = await decryptCheckin({ ...checkin }, env);
  return jsonResponse({ checkin: decrypted }, 200, origin, env.ALLOWED_ORIGIN);
}

async function handleAdminPhoto(env, id, request, origin) {
  if (!await verifyAdmin(request, env)) {
    return jsonResponse({ error: 'Unauthorized' }, 401, origin, env.ALLOWED_ORIGIN);
  }

  const result = await env.DB.prepare('SELECT passport_photo FROM checkins WHERE id = ?').bind(id).first();
  if (!result || !result.passport_photo) {
    return jsonResponse({ error: 'No photo found' }, 404, origin, env.ALLOWED_ORIGIN);
  }

  // Check if stored in R2
  if (result.passport_photo.startsWith('r2:') && env.PHOTOS) {
    const r2Key = result.passport_photo.slice(3);
    const obj = await env.PHOTOS.get(r2Key);
    if (!obj) {
      return jsonResponse({ error: 'Photo deleted or expired' }, 404, origin, env.ALLOWED_ORIGIN);
    }
    const bytes = await obj.arrayBuffer();
    const base64 = btoa(String.fromCharCode(...new Uint8Array(bytes)));
    const contentType = obj.httpMetadata?.contentType || 'image/jpeg';
    const dataUrl = `data:${contentType};base64,${base64}`;
    return jsonResponse({ photo: dataUrl }, 200, origin, env.ALLOWED_ORIGIN);
  }

  // Legacy D1 base64 storage
  return jsonResponse({ photo: result.passport_photo }, 200, origin, env.ALLOWED_ORIGIN);
}

async function handleAdminDelete(env, id, request, origin) {
  if (!await verifyAdmin(request, env)) {
    return jsonResponse({ error: 'Unauthorized' }, 401, origin, env.ALLOWED_ORIGIN);
  }

  // Delete R2 photo if exists
  if (env.PHOTOS) {
    const photo = await env.DB.prepare('SELECT passport_photo FROM checkins WHERE id = ?').bind(id).first();
    if (photo && photo.passport_photo && photo.passport_photo.startsWith('r2:')) {
      try {
        await env.PHOTOS.delete(photo.passport_photo.slice(3));
      } catch (e) {
        console.error('Failed to delete R2 photo:', e);
      }
    }
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

  // Admin memo update
  if (data.admin_memo !== undefined) {
    const memo = String(data.admin_memo || '').slice(0, 1000);
    updates.push('admin_memo = ?');
    params.push(memo);
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
    'SELECT name, furigana, adults, children, checkin_date, checkout_date, phone, email, zipcode, address, is_foreign, nationality, passport_no, transport, allergies, notes, admin_memo, receipt_name, age, booking_site, sns_consent, photo_consent, companion_relation, migration_interest, status, created_at FROM checkins ORDER BY created_at DESC'
  ).all();

  // Decrypt sensitive fields for CSV export
  const decryptedResults = await decryptCheckins(result.results || [], env);

  const headers = ['氏名', 'フリガナ', '大人', '子供', 'チェックイン', 'チェックアウト', '電話番号', 'メール', '郵便番号', '住所', '外国籍', '国籍', 'パスポート番号', '交通手段', 'アレルギー', '備考', 'オーナーメモ', '領収書宛名', '年齢', '予約サイト', 'SNS掲載', '記念撮影', '同行者関係', '移住興味', 'ステータス', '登録日時'];
  const csvRows = [headers.join(',')];

  for (const row of decryptedResults) {
    const csvRow = [
      row.name, row.furigana, row.adults, row.children,
      row.checkin_date, row.checkout_date, row.phone, row.email,
      row.zipcode, row.address, row.is_foreign ? 'はい' : 'いいえ',
      row.nationality, row.passport_no, row.transport,
      row.allergies, row.notes, row.admin_memo, row.receipt_name,
      row.age || '', row.booking_site || '', row.sns_consent || '', row.photo_consent || '', row.companion_relation || '', row.migration_interest || '',
      row.status, row.created_at
    ].map(v => `"${String(v || '').replace(/"/g, '""')}"`);
    csvRows.push(csvRow.join(','));
  }

  const csv = '\uFEFF' + csvRows.join('\n'); // BOM for Excel

  return new Response(csv, {
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="checkins.csv"',
      ...corsHeaders(origin, env.ALLOWED_ORIGIN),
      ...securityHeaders(),
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
    "SELECT strftime('%Y-%m', checkin_date) as month, SUM(adults + children) as count FROM checkins WHERE 1=1" + dateFilter + " GROUP BY month ORDER BY month DESC LIMIT 24"
  );
  const nationalityStmt = env.DB.prepare(
    "SELECT nationality, SUM(adults + children) as count FROM checkins WHERE is_foreign = 1 AND nationality != ''" + dateFilter + " GROUP BY nationality ORDER BY count DESC"
  );
  const avgStmt = env.DB.prepare(
    "SELECT AVG(julianday(checkout_date) - julianday(checkin_date)) as avg_stay FROM checkins WHERE checkout_date IS NOT NULL AND checkin_date IS NOT NULL" + dateFilter
  );
  const totalStmt = env.DB.prepare(
    "SELECT SUM(adults + children) as total FROM checkins WHERE 1=1" + dateFilter
  );
  const weekdayStmt = env.DB.prepare(
    "SELECT CAST(strftime('%w', checkin_date) AS INTEGER) as dow, SUM(adults + children) as count FROM checkins WHERE 1=1" + dateFilter + " GROUP BY dow ORDER BY dow"
  );
  const repeaterStmt = env.DB.prepare(
    "SELECT name, COUNT(*) as visits FROM checkins WHERE 1=1" + dateFilter + " GROUP BY name HAVING visits > 1 ORDER BY visits DESC LIMIT 20"
  );
  const bookingSiteStmt = env.DB.prepare(
    "SELECT booking_site, SUM(adults + children) as count FROM checkins WHERE booking_site != '' AND booking_site IS NOT NULL" + dateFilter + " GROUP BY booking_site ORDER BY count DESC"
  );
  const ageGroupStmt = env.DB.prepare(
    "SELECT CASE WHEN age < 20 THEN '10代以下' WHEN age < 30 THEN '20代' WHEN age < 40 THEN '30代' WHEN age < 50 THEN '40代' WHEN age < 60 THEN '50代' ELSE '60代以上' END as age_group, SUM(adults + children) as count FROM checkins WHERE age > 0" + dateFilter + " GROUP BY age_group ORDER BY MIN(age)"
  );
  const prefectureStmt = env.DB.prepare(
    "SELECT CASE WHEN address LIKE '北海道%' THEN '北海道' WHEN address LIKE '青森県%' THEN '青森県' WHEN address LIKE '岩手県%' THEN '岩手県' WHEN address LIKE '宮城県%' THEN '宮城県' WHEN address LIKE '秋田県%' THEN '秋田県' WHEN address LIKE '山形県%' THEN '山形県' WHEN address LIKE '福島県%' THEN '福島県' WHEN address LIKE '茨城県%' THEN '茨城県' WHEN address LIKE '栃木県%' THEN '栃木県' WHEN address LIKE '群馬県%' THEN '群馬県' WHEN address LIKE '埼玉県%' THEN '埼玉県' WHEN address LIKE '千葉県%' THEN '千葉県' WHEN address LIKE '東京都%' THEN '東京都' WHEN address LIKE '神奈川県%' THEN '神奈川県' WHEN address LIKE '新潟県%' THEN '新潟県' WHEN address LIKE '富山県%' THEN '富山県' WHEN address LIKE '石川県%' THEN '石川県' WHEN address LIKE '福井県%' THEN '福井県' WHEN address LIKE '山梨県%' THEN '山梨県' WHEN address LIKE '長野県%' THEN '長野県' WHEN address LIKE '岐阜県%' THEN '岐阜県' WHEN address LIKE '静岡県%' THEN '静岡県' WHEN address LIKE '愛知県%' THEN '愛知県' WHEN address LIKE '三重県%' THEN '三重県' WHEN address LIKE '滋賀県%' THEN '滋賀県' WHEN address LIKE '京都府%' THEN '京都府' WHEN address LIKE '大阪府%' THEN '大阪府' WHEN address LIKE '兵庫県%' THEN '兵庫県' WHEN address LIKE '奈良県%' THEN '奈良県' WHEN address LIKE '和歌山県%' THEN '和歌山県' WHEN address LIKE '鳥取県%' THEN '鳥取県' WHEN address LIKE '島根県%' THEN '島根県' WHEN address LIKE '岡山県%' THEN '岡山県' WHEN address LIKE '広島県%' THEN '広島県' WHEN address LIKE '山口県%' THEN '山口県' WHEN address LIKE '徳島県%' THEN '徳島県' WHEN address LIKE '香川県%' THEN '香川県' WHEN address LIKE '愛媛県%' THEN '愛媛県' WHEN address LIKE '高知県%' THEN '高知県' WHEN address LIKE '福岡県%' THEN '福岡県' WHEN address LIKE '佐賀県%' THEN '佐賀県' WHEN address LIKE '長崎県%' THEN '長崎県' WHEN address LIKE '熊本県%' THEN '熊本県' WHEN address LIKE '大分県%' THEN '大分県' WHEN address LIKE '宮崎県%' THEN '宮崎県' WHEN address LIKE '鹿児島県%' THEN '鹿児島県' WHEN address LIKE '沖縄県%' THEN '沖縄県' ELSE 'その他' END as prefecture, SUM(adults + children) as count FROM checkins WHERE address IS NOT NULL AND address != '' AND is_foreign = 0" + dateFilter + " GROUP BY prefecture ORDER BY count DESC"
  );

  const bind = (stmt) => dateParams.length > 0 ? stmt.bind(...dateParams) : stmt;

  const [monthlyResult, nationalityResult, avgResult, totalResult, weekdayResult, repeaterResult, bookingSiteResult, ageGroupResult, prefectureResult] = await Promise.all([
    bind(monthlyStmt).all(),
    bind(nationalityStmt).all(),
    bind(avgStmt).first(),
    bind(totalStmt).first(),
    bind(weekdayStmt).all(),
    bind(repeaterStmt).all(),
    bind(bookingSiteStmt).all(),
    bind(ageGroupStmt).all(),
    bind(prefectureStmt).all(),
  ]);

  return jsonResponse({
    monthly: monthlyResult.results || [],
    nationalities: nationalityResult.results || [],
    avg_stay: avgResult ? Math.round((avgResult.avg_stay || 0) * 10) / 10 : 0,
    total: totalResult ? totalResult.total : 0,
    weekday: weekdayResult.results || [],
    repeaters: repeaterResult.results || [],
    booking_sites: bookingSiteResult.results || [],
    age_groups: ageGroupResult.results || [],
    prefectures: prefectureResult.results || [],
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

  const decrypted = await decryptCheckins(result.results || [], env);
  return jsonResponse({ month, checkins: decrypted }, 200, origin, env.ALLOWED_ORIGIN);
}

// --- Main Router ---

export default {
  async scheduled(event, env, ctx) {
    const today = new Date().toISOString().split('T')[0];

    // Auto-checkout: JST 06:00 daily (UTC 21:00)
    const checkoutResult = await env.DB.prepare(
      "UPDATE checkins SET status = 'checked_out' WHERE checkout_date < ? AND status = 'checked_in'"
    ).bind(today).run();
    console.log(`Auto-checkout: ${checkoutResult.meta.changes} records updated`);

    // Auto-delete passport photos from R2: 30 days after checkout
    if (env.PHOTOS) {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - PHOTO_RETENTION_DAYS);
      const cutoff = cutoffDate.toISOString().split('T')[0];

      const expiredPhotos = await env.DB.prepare(
        "SELECT id, passport_photo FROM checkins WHERE status = 'checked_out' AND checkout_date < ? AND passport_photo IS NOT NULL AND passport_photo != ''"
      ).bind(cutoff).all();

      let photoDeleted = 0;
      for (const row of (expiredPhotos.results || [])) {
        if (row.passport_photo && row.passport_photo.startsWith('r2:')) {
          const r2Key = row.passport_photo.slice(3);
          try {
            await env.PHOTOS.delete(r2Key);
            await env.DB.prepare('UPDATE checkins SET passport_photo = NULL WHERE id = ?').bind(row.id).run();
            photoDeleted++;
          } catch (e) {
            console.error(`Failed to delete R2 photo for ${row.id}:`, e);
          }
        } else if (row.passport_photo && !row.passport_photo.startsWith('r2:')) {
          // Legacy D1 base64 photo — clear it
          await env.DB.prepare('UPDATE checkins SET passport_photo = NULL WHERE id = ?').bind(row.id).run();
          photoDeleted++;
        }
      }
      if (photoDeleted > 0) {
        console.log(`Auto-delete photos: ${photoDeleted} expired passport photos removed`);
      }
    }

    // Clean up expired photo upload tokens
    const nowSec = Math.floor(Date.now() / 1000);
    await env.DB.prepare('DELETE FROM photo_tokens WHERE expires_at < ?').bind(nowSec).run();

    // Weekly backup: D1 → R2 (every Sunday = day 0)
    if (env.PHOTOS) {
      const dayOfWeek = new Date().getUTCDay();
      if (dayOfWeek === 0) { // Sunday
        try {
          const allData = await env.DB.prepare(
            'SELECT * FROM checkins ORDER BY created_at DESC'
          ).all();
          const backup = {
            timestamp: new Date().toISOString(),
            record_count: (allData.results || []).length,
            checkins: allData.results || [],
          };
          const backupKey = `backups/checkins-${today}.json`;
          await env.PHOTOS.put(backupKey, JSON.stringify(backup), {
            httpMetadata: { contentType: 'application/json' },
          });
          console.log(`Backup: ${backup.record_count} records saved to R2 (${backupKey})`);

          // Keep only last 12 backups (3 months)
          const list = await env.PHOTOS.list({ prefix: 'backups/checkins-' });
          const backupFiles = list.objects.sort((a, b) => a.key.localeCompare(b.key));
          if (backupFiles.length > 12) {
            const toDelete = backupFiles.slice(0, backupFiles.length - 12);
            for (const file of toDelete) {
              await env.PHOTOS.delete(file.key);
            }
            console.log(`Backup cleanup: ${toDelete.length} old backups removed`);
          }
        } catch (e) {
          console.error('Backup failed:', e);
        }
      }
    }

    // Auto-delete personal data: 3 years after checkout (旅館業法準拠)
    const dataRetentionCutoff = new Date();
    dataRetentionCutoff.setFullYear(dataRetentionCutoff.getFullYear() - DATA_RETENTION_YEARS);
    const dataCutoff = dataRetentionCutoff.toISOString().split('T')[0];

    const deleteResult = await env.DB.prepare(
      "DELETE FROM checkins WHERE status = 'checked_out' AND checkout_date < ?"
    ).bind(dataCutoff).run();
    if (deleteResult.meta.changes > 0) {
      console.log(`Auto-delete data: ${deleteResult.meta.changes} records older than ${DATA_RETENTION_YEARS} years removed`);
    }
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
        headers: { ...corsHeaders(origin, env.ALLOWED_ORIGIN), ...securityHeaders() },
      });
    }

    try {
      // Public endpoints
      if (path === '/checkin' && method === 'POST') {
        return await handleCheckin(request, env, origin);
      }
      if (path === '/checkin/photo' && method === 'POST') {
        return await handlePhotoUpload(request, env, origin);
      }

      // Auth endpoints
      if (path === '/admin/login' && method === 'POST') {
        return await handleLogin(request, env, origin);
      }
      if (path === '/admin/change-password' && method === 'POST') {
        return await handleChangePassword(request, env, origin);
      }

      // Admin endpoints
      if (path === '/admin/checkins' && method === 'GET') {
        return await handleAdminCheckins(request, env, origin);
      }
      if (path === '/admin/stats' && method === 'GET') {
        return await handleAdminStats(request, env, origin);
      }
      const monthlyMatch = path.match(/^\/admin\/stats\/monthly\/(\d{4}-\d{2})$/);
      if (monthlyMatch && method === 'GET') {
        return await handleAdminStatsMonthly(request, env, origin, monthlyMatch[1]);
      }
      if (path === '/admin/checkins/csv' && method === 'GET') {
        return await handleAdminCsvExport(request, env, origin);
      }

      const checkinMatch = path.match(/^\/admin\/checkins\/([a-f0-9-]+)$/);
      if (checkinMatch) {
        const id = checkinMatch[1];
        if (method === 'GET') return await handleAdminCheckinDetail(env, id, request, origin);
        if (method === 'DELETE') return await handleAdminDelete(env, id, request, origin);
        if (method === 'PUT') return await handleAdminUpdate(env, id, request, origin);
      }

      const photoMatch = path.match(/^\/admin\/photo\/([a-f0-9-]+)$/);
      if (photoMatch && method === 'GET') {
        return await handleAdminPhoto(env, photoMatch[1], request, origin);
      }

      return jsonResponse({ error: 'Not found' }, 404, origin, env.ALLOWED_ORIGIN);
    } catch (e) {
      console.error('Unhandled error:', e.message || e, e.stack || '');
      return jsonResponse({ error: 'Internal server error' }, 500, origin, env.ALLOWED_ORIGIN);
    }
  },
};
