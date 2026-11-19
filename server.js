require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const xss = require('xss');
const { Pool } = require('pg');

// ---------- Config ----------
const cmd = process.argv[2];
const IS_CLI = ['generate-pin', 'init-db'].includes(cmd);
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const { DATABASE_URL, JWT_SECRET, CREDENTIAL_KEY } = process.env;

if (!DATABASE_URL) { console.error('DATABASE_URL belum diisi di .env'); process.exit(1); }
if (!IS_CLI && (!JWT_SECRET || JWT_SECRET.length < 32 || !CREDENTIAL_KEY || CREDENTIAL_KEY.length < 32)) {
  console.error('JWT_SECRET dan CREDENTIAL_KEY wajib diisi (minimal 32 karakter) di .env');
  process.exit(1);
}

const CATEGORIES = ['Resources', 'Academic', 'Project', 'Work', 'Google Drive', 'Google Maps',
  'Github', 'Japanese', 'Instagram', 'Tiktok', 'Discord', 'Invitation'];

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 5 });

// ---------- Crypto (credential AES-256-GCM) ----------
const encKey = crypto.createHash('sha256').update(String(CREDENTIAL_KEY || '')).digest();
function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', encKey, iv);
  const enc = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64');
}
function decrypt(b64) {
  const buf = Buffer.from(b64, 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', encKey, buf.subarray(0, 12));
  d.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');
}

// ---------- Helpers ----------
const h = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const genCode = () => crypto.randomBytes(6).toString('base64url').slice(0, 8);

function cleanCredential(raw) {
  if (raw === undefined || raw === null || raw === '') return { value: null };
  if (typeof raw !== 'string') return { error: 'Format credential tidak valid' };

  const html = xss(raw, {
    whiteList: {
      p: [], br: [], strong: [], em: [], u: [], s: [],
      ol: [], ul: [], li: [], h1: [], h2: [], h3: [], span: [],
      a: ['href', 'target', 'rel']
    },
    onTagAttr: function (tag, name, value, isWhiteAttr) {
      if (tag === 'a' && name === 'href') {
        if (!/^https?:\/\//i.test(value)) return '';
        return 'href="' + xss.escapeAttrValue(value) + '" target="_blank" rel="noopener noreferrer"';
      }
    }
  });

  const text = html.replace(/<[^>]*>/g, '').trim();
  if (!text) return { value: null };
  if (html.length > 5000) return { error: 'Credential terlalu panjang (maks 5000 karakter)' };
  return { value: html };
}

function validateLink(b = {}) {
  const name = String(b.name || '').trim();
  const url = String(b.url || '').trim();
  const category = String(b.category || '').trim();
  if (!name || name.length > 120) return { error: 'Nama link wajib diisi (maks 120 karakter)' };
  try {
    const u = new URL(url);
    if (!['http:', 'https:'].includes(u.protocol)) throw new Error();
  } catch { return { error: 'Link harus berupa URL http:// atau https:// yang valid' }; }
  if (!CATEGORIES.includes(category)) return { error: 'Kategori tidak valid' };
  const cred = cleanCredential(b.credential);
  if (cred.error) return { error: cred.error };
  return { name, url, category, credential: cred.value };
}

// ---------- Notes helpers ----------
function cleanNoteHtml(raw) {
  if (typeof raw !== 'string') return { error: 'Format isi note tidak valid' };
  const html = xss(raw, {
    whiteList: {
      p: ['class'], br: [], strong: [], em: [], u: [], s: [], span: ['class'],
      h1: ['class'], h2: ['class'], h3: ['class'],
      blockquote: ['class'], pre: ['class'], code: [],
      ol: ['class'], ul: ['class'], li: ['class'],
      a: ['href', 'target', 'rel']
    },
    onTagAttr: function (tag, name, value) {
      if (tag === 'a' && name === 'href') {
        if (!/^https?:\/\//i.test(value)) return '';
        return 'href="' + xss.escapeAttrValue(value) + '" target="_blank" rel="noopener noreferrer"';
      }
      if (name === 'class') {
        // hanya class bawaan Quill (ql-align-center, ql-indent-1, ql-syntax, dst)
        return /^(ql-[a-z0-9-]+)( ql-[a-z0-9-]+)*$/.test(value) ? 'class="' + value + '"' : '';
      }
    }
  });
  const text = html.replace(/<[^>]*>/g, '').trim();
  if (!text) return { error: 'Isi note wajib diisi' };
  if (html.length > 40000) return { error: 'Isi note terlalu panjang (maks 40.000 karakter)' };
  return { value: html };
}

function validateNote(b = {}) {
  const title = String(b.title || '').trim();
  const category = String(b.category || '').trim();
  if (!title || title.length > 150) return { error: 'Judul wajib diisi (maks 150 karakter)' };
  if (category.length > 40) return { error: 'Kategori maks 40 karakter' };
  const c = cleanNoteHtml(b.content);
  if (c.error) return { error: c.error };
  return { title, category: category || null, content: c.value };
}

const NOTE_LIST_COLS = `id, title, category, created_at, updated_at,
  left(btrim(regexp_replace(regexp_replace(content, '<[^>]*>', ' ', 'g'), '\\s+', ' ', 'g')), 180) AS excerpt`;
const NOTE_FULL_COLS = 'id, title, category, content, created_at, updated_at';

const LINK_COLS = `id, code, name, url, category, (credential_enc IS NOT NULL) AS has_credential,
  click_count, scan_count, created_at, updated_at`;

// ---------- Auth ----------
function getSession(req) {
  const t = req.cookies && req.cookies.hiro_token;
  if (!t) return null;
  try { return jwt.verify(t, JWT_SECRET, { algorithms: ['HS256'] }); } catch { return null; }
}
async function isAuthed(req) {
  const s = getSession(req);
  if (!s) return false;
  const { rows } = await pool.query('SELECT pin_version FROM admin_auth WHERE id = 1');
  return !!rows[0] && rows[0].pin_version === s.pv;
}
const requireApi = h(async (req, res, next) => {
  if (await isAuthed(req)) return next();
  res.status(401).json({ error: 'Sesi berakhir, silakan login kembali' });
});
const requirePage = h(async (req, res, next) => {
  if (await isAuthed(req)) return next();
  res.redirect('/');
});

// ---------- App ----------
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());

// Header keamanan dasar (manual, tanpa helmet)
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Referrer-Policy', 'same-origin');
  res.set('X-Frame-Options', 'DENY');
  if (req.path.startsWith('/api') || ['/', '/dashboard', '/manage-link', '/notes'].includes(req.path)) {
    res.set('Cache-Control', 'no-store');
  }
  next();
});

// Proteksi CSRF tambahan (selain cookie SameSite=Strict)
app.use('/api', (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (req.get('X-Requested-With') !== 'XMLHttpRequest') return res.status(403).json({ error: 'Permintaan ditolak' });
  next();
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 5, skipSuccessfulRequests: true,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Terlalu banyak percobaan. Coba lagi dalam 15 menit.' }
});
const redirectLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });

// ---------- Pages ----------
app.get('/', h(async (req, res) => {
  if (await isAuthed(req)) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
}));
app.get('/dashboard', requirePage, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'dashboard.html')));
app.get('/manage-link', requirePage, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'manage-link.html')));
app.get('/notes', requirePage, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'notes.html')));
app.use('/admin', (req, res) => res.status(404).end());
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// ---------- Auth API ----------
app.post('/api/auth/login', loginLimiter, h(async (req, res) => {
  const pin = String((req.body && req.body.pin) || '');
  if (!/^\d{6}$/.test(pin)) return res.status(400).json({ error: 'PIN harus 6 digit angka' });
  const { rows } = await pool.query('SELECT pin_hash, pin_version FROM admin_auth WHERE id = 1');
  const ok = rows[0] ? await bcrypt.compare(pin, rows[0].pin_hash) : false;
  if (!ok) return res.status(401).json({ error: 'PIN salah' });
  const token = jwt.sign({ sub: 'owner', pv: rows[0].pin_version }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '12h' });
  res.cookie('hiro_token', token, { httpOnly: true, sameSite: 'strict', secure: IS_PROD, maxAge: 12 * 3600 * 1000, path: '/' });
  res.json({ ok: true });
}));

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('hiro_token', { httpOnly: true, sameSite: 'strict', secure: IS_PROD, path: '/' });
  res.json({ ok: true });
});

// ---------- Profile ----------
app.get('/api/profile', requireApi, h(async (req, res) => {
  const { rows } = await pool.query('SELECT display_name, headline, bio FROM profile WHERE id = 1');
  res.json(rows[0] || { display_name: 'Owner', headline: '', bio: '' });
}));

app.put('/api/profile', requireApi, h(async (req, res) => {
  const b = req.body || {};
  const display_name = String(b.display_name || '').trim();
  const headline = String(b.headline || '').trim();
  const bio = String(b.bio || '').trim();
  if (!display_name || display_name.length > 80) return res.status(400).json({ error: 'Nama wajib diisi (maks 80 karakter)' });
  if (headline.length > 120) return res.status(400).json({ error: 'Headline maks 120 karakter' });
  if (bio.length > 300) return res.status(400).json({ error: 'Bio maks 300 karakter' });
  const { rows } = await pool.query(
    `INSERT INTO profile (id, display_name, headline, bio) VALUES (1, $1, $2, $3)
     ON CONFLICT (id) DO UPDATE SET display_name = $1, headline = $2, bio = $3, updated_at = now()
     RETURNING display_name, headline, bio`, [display_name, headline, bio]);
  res.json(rows[0]);
}));

// ---------- Stats ----------
app.get('/api/stats', requireApi, h(async (req, res) => {
  const [tot, cat, top, monthly] = await Promise.all([
    pool.query(`SELECT COUNT(*)::int AS total, COALESCE(SUM(click_count),0)::int AS clicks,
                COALESCE(SUM(scan_count),0)::int AS scans, COUNT(credential_enc)::int AS with_cred,
                COUNT(DISTINCT category)::int AS cats FROM links`),
    pool.query(`SELECT category, COUNT(*)::int AS count FROM links GROUP BY category ORDER BY count DESC, category`),
    pool.query(`SELECT id, name, category, (click_count + scan_count)::int AS visits FROM links
                ORDER BY visits DESC, created_at DESC LIMIT 5`),
    pool.query(`SELECT to_char(m, 'Mon') AS label, COALESCE(c.n, 0)::int AS n
                FROM generate_series(date_trunc('month', now()) - interval '5 months', date_trunc('month', now()), interval '1 month') m
                LEFT JOIN (SELECT date_trunc('month', created_at) AS mm, COUNT(*) AS n FROM links GROUP BY 1) c ON c.mm = m
                ORDER BY m`)
  ]);
  res.json({ ...tot.rows[0], byCategory: cat.rows, top: top.rows, monthly: monthly.rows });
}));

// ---------- Links CRUD ----------
app.get('/api/links', requireApi, h(async (req, res) => {
  const search = String(req.query.search || '').trim().slice(0, 100);
  const category = String(req.query.category || '').trim();
  const where = []; const params = [];
  if (search) {
    params.push('%' + search.replace(/[\\%_]/g, '\\$&') + '%');
    where.push(`(name ILIKE $${params.length} OR url ILIKE $${params.length} OR category ILIKE $${params.length})`);
  }
  if (category) {
    if (!CATEGORIES.includes(category)) return res.status(400).json({ error: 'Kategori tidak valid' });
    params.push(category);
    where.push(`category = $${params.length}`);
  }
  const { rows } = await pool.query(
    `SELECT ${LINK_COLS} FROM links ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY updated_at DESC, id DESC`, params);
  res.json({ links: rows });
}));

app.post('/api/links', requireApi, h(async (req, res) => {
  const v = validateLink(req.body);
  if (v.error) return res.status(400).json({ error: v.error });
  const credEnc = v.credential ? encrypt(v.credential) : null;
  for (let i = 0; i < 5; i++) {
    try {
      const { rows } = await pool.query(
        `INSERT INTO links (code, name, url, category, credential_enc) VALUES ($1,$2,$3,$4,$5) RETURNING ${LINK_COLS}`,
        [genCode(), v.name, v.url, v.category, credEnc]);
      return res.status(201).json({ link: rows[0] });
    } catch (e) { if (e.code !== '23505') throw e; }
  }
  res.status(500).json({ error: 'Gagal membuat kode link, coba lagi' });
}));

app.put('/api/links/:id', requireApi, h(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'ID tidak valid' });
  const v = validateLink(req.body);
  if (v.error) return res.status(400).json({ error: v.error });
  const { rows } = await pool.query(
    `UPDATE links SET name=$1, url=$2, category=$3, credential_enc=$4, updated_at=now()
     WHERE id=$5 RETURNING ${LINK_COLS}`,
    [v.name, v.url, v.category, v.credential ? encrypt(v.credential) : null, id]);
  if (!rows[0]) return res.status(404).json({ error: 'Link tidak ditemukan' });
  res.json({ link: rows[0] });
}));

app.delete('/api/links/:id', requireApi, h(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'ID tidak valid' });
  const r = await pool.query('DELETE FROM links WHERE id = $1', [id]);
  if (!r.rowCount) return res.status(404).json({ error: 'Link tidak ditemukan' });
  res.json({ ok: true });
}));

app.get('/api/links/:id/credential', requireApi, h(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'ID tidak valid' });
  const { rows } = await pool.query('SELECT credential_enc FROM links WHERE id = $1', [id]);
  if (!rows[0]) return res.status(404).json({ error: 'Link tidak ditemukan' });
  if (!rows[0].credential_enc) return res.json({ credential: '' });
  try { res.json({ credential: decrypt(rows[0].credential_enc) }); }
  catch { res.status(500).json({ error: 'Credential tidak dapat didekripsi (cek CREDENTIAL_KEY)' }); }
}));

// ---------- Notes CRUD ----------
app.get('/api/notes', requireApi, h(async (req, res) => {
  const search = String(req.query.search || '').trim().slice(0, 100);
  const category = String(req.query.category || '').trim().slice(0, 40);
  const where = []; const params = [];
  if (search) {
    params.push('%' + search.replace(/[\\%_]/g, '\\$&') + '%');
    where.push(`(title ILIKE $${params.length} OR category ILIKE $${params.length} OR content ILIKE $${params.length})`);
  }
  if (category) { params.push(category); where.push(`category = $${params.length}`); }
  const [list, cats] = await Promise.all([
    pool.query(`SELECT ${NOTE_LIST_COLS} FROM notes ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY updated_at DESC, id DESC`, params),
    pool.query(`SELECT category, COUNT(*)::int AS count FROM notes WHERE category IS NOT NULL GROUP BY category ORDER BY category`)
  ]);
  res.json({ notes: list.rows, categories: cats.rows });
}));

app.get('/api/notes/:id', requireApi, h(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'ID tidak valid' });
  const { rows } = await pool.query(`SELECT ${NOTE_FULL_COLS} FROM notes WHERE id = $1`, [id]);
  if (!rows[0]) return res.status(404).json({ error: 'Note tidak ditemukan' });
  res.json({ note: rows[0] });
}));

app.post('/api/notes', requireApi, h(async (req, res) => {
  const v = validateNote(req.body);
  if (v.error) return res.status(400).json({ error: v.error });
  const { rows } = await pool.query(
    `INSERT INTO notes (title, category, content) VALUES ($1,$2,$3) RETURNING ${NOTE_FULL_COLS}`,
    [v.title, v.category, v.content]);
  res.status(201).json({ note: rows[0] });
}));

app.put('/api/notes/:id', requireApi, h(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'ID tidak valid' });
  const v = validateNote(req.body);
  if (v.error) return res.status(400).json({ error: v.error });
  const { rows } = await pool.query(
    `UPDATE notes SET title=$1, category=$2, content=$3, updated_at=now() WHERE id=$4 RETURNING ${NOTE_FULL_COLS}`,
    [v.title, v.category, v.content, id]);
  if (!rows[0]) return res.status(404).json({ error: 'Note tidak ditemukan' });
  res.json({ note: rows[0] });
}));

app.delete('/api/notes/:id', requireApi, h(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'ID tidak valid' });
  const r = await pool.query('DELETE FROM notes WHERE id = $1', [id]);
  if (!r.rowCount) return res.status(404).json({ error: 'Note tidak ditemukan' });
  res.json({ ok: true });
}));

// ---------- Public redirect (target QR) ----------
app.get('/s/:code', redirectLimiter, h(async (req, res) => {
  const code = req.params.code;
  const notFound = () => res.status(404).type('html').send(
    `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
     <body style="font-family:system-ui;background:#f4f1e4;color:#3a2d23;display:grid;place-items:center;min-height:100vh;margin:0;text-align:center;padding:24px">
     <div><div style="font-size:48px">🍃</div><h1>Link tidak ditemukan</h1><p>Link ini mungkin sudah dihapus oleh pemiliknya.</p></div></body>`);
  if (!/^[A-Za-z0-9_-]{6,16}$/.test(code)) return notFound();
  const qr = req.query.src === 'qr';
  const { rows } = await pool.query(
    `UPDATE links SET click_count = click_count + $1, scan_count = scan_count + $2, last_accessed_at = now()
     WHERE code = $3 RETURNING url`, [qr ? 0 : 1, qr ? 1 : 0, code]);
  if (!rows[0]) return notFound();
  res.redirect(302, rows[0].url);
}));

// ---------- Errors ----------
app.use('/api', (req, res) => res.status(404).json({ error: 'Endpoint tidak ditemukan' }));
app.use((err, req, res, next) => {
  console.error(err);
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Format data tidak valid' });
  res.status(500).json({ error: 'Terjadi kesalahan pada server' });
});

// ---------- CLI & Start ----------
async function generatePin() {
  let pin = process.argv[3]; // opsional: node server.js generate-pin 123456
  if (pin === undefined) {
    const rl = require('readline').createInterface({ input: process.stdin, output: process.stdout });
    const ans = await new Promise((r) => rl.question('  Masukkan PIN 6 digit (kosongkan untuk acak): ', r));
    rl.close();
    pin = ans.trim() || undefined;
  }
  if (pin === undefined) {
    do { pin = String(crypto.randomInt(0, 1000000)).padStart(6, '0'); } while (/^(\d)\1{5}$/.test(pin));
  } else if (!/^\d{6}$/.test(pin)) {
    throw new Error('PIN harus tepat 6 digit angka');
  }
  const hash = await bcrypt.hash(pin, 12);
  await pool.query(
    `INSERT INTO admin_auth (id, pin_hash, pin_version) VALUES (1, $1, 1)
     ON CONFLICT (id) DO UPDATE SET pin_hash = $1, pin_version = admin_auth.pin_version + 1, updated_at = now()`, [hash]);
  console.log('\n  🌿 Hiro Space Link — PIN baru berhasil dibuat');
  console.log('  ┌──────────────┐');
  console.log(`  │  PIN: ${pin}  │`);
  console.log('  └──────────────┘');
  console.log('  Simpan baik-baik. Sesi login lama otomatis keluar.\n');
}

if (require.main === module) {
  (async () => {
    try {
      if (cmd === 'generate-pin') { await generatePin(); }
      else if (cmd === 'init-db') {
        await pool.query(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));
        console.log('✅ Schema database siap.');
      } else {
        app.listen(PORT, () => console.log(`🌿 Hiro Space Link berjalan di http://localhost:${PORT}`));
        return;
      }
      await pool.end();
    } catch (e) { console.error('Error:', e.message); process.exit(1); }
  })();
}

module.exports = app;