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
  status TEXT DEFAULT 'pending',
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS admin_tokens (
  token TEXT PRIMARY KEY,
  created_at TEXT DEFAULT (datetime('now'))
);
