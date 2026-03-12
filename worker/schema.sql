CREATE TABLE IF NOT EXISTS checkins (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  furigana TEXT,
  adults INTEGER DEFAULT 1,
  children INTEGER DEFAULT 0,
  checkin_date TEXT NOT NULL,
  checkout_date TEXT NOT NULL,
  phone TEXT NOT NULL,
  email TEXT,
  zipcode TEXT,
  address TEXT,
  is_foreign INTEGER DEFAULT 0,
  nationality TEXT,
  passport_no TEXT,
  passport_photo TEXT,
  transport TEXT,
  allergies TEXT,
  notes TEXT,
  admin_memo TEXT DEFAULT '',
  status TEXT DEFAULT 'pending',
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS admin_tokens (
  token TEXT PRIMARY KEY,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS rate_limits (
  ip TEXT,
  timestamp INTEGER
);

CREATE TABLE IF NOT EXISTS login_attempts (
  ip TEXT,
  timestamp INTEGER,
  success INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS admin_passwords (
  id INTEGER PRIMARY KEY,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS photo_tokens (
  token TEXT PRIMARY KEY,
  checkin_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
