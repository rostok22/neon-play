require('dotenv').config();

const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const Parser = require('rss-parser');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === 'production';
const SESSION_SECRET = process.env.SESSION_SECRET || 'local-development-secret-change-me';

const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'vice-city.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_url TEXT NOT NULL,
    article_title TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS comments_article_idx ON comments(article_url, created_at DESC);
  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    sess TEXT NOT NULL,
    expire INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_expire_idx ON sessions(expire);
`);

// Small SQLite-backed session store: sessions survive server restarts.
class SQLiteSessionStore extends session.Store {
  constructor(database) {
    super();
    this.database = database;
    this.getStatement = database.prepare('SELECT sess, expire FROM sessions WHERE sid = ?');
    this.setStatement = database.prepare('INSERT INTO sessions (sid, sess, expire) VALUES (?, ?, ?) ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expire = excluded.expire');
    this.deleteStatement = database.prepare('DELETE FROM sessions WHERE sid = ?');
    this.touchStatement = database.prepare('UPDATE sessions SET sess = ?, expire = ? WHERE sid = ?');
    database.prepare('DELETE FROM sessions WHERE expire <= ?').run(Date.now());
  }
  get(sid, callback) {
    try {
      const row = this.getStatement.get(sid);
      if (!row) return callback(null, null);
      if (row.expire <= Date.now()) {
        this.deleteStatement.run(sid);
        return callback(null, null);
      }
      callback(null, JSON.parse(row.sess));
    } catch (error) { callback(error); }
  }
  set(sid, sess, callback = () => {}) {
    try {
      const expires = sess.cookie && sess.cookie.expires
        ? new Date(sess.cookie.expires).getTime()
        : Date.now() + (sess.cookie?.maxAge || 86400000);
      this.setStatement.run(sid, JSON.stringify(sess), expires);
      callback(null);
    } catch (error) { callback(error); }
  }
  destroy(sid, callback = () => {}) {
    try { this.deleteStatement.run(sid); callback(null); }
    catch (error) { callback(error); }
  }
  touch(sid, sess, callback = () => {}) {
    try {
      const expires = sess.cookie && sess.cookie.expires
        ? new Date(sess.cookie.expires).getTime()
        : Date.now() + (sess.cookie?.maxAge || 86400000);
      this.touchStatement.run(JSON.stringify(sess), expires, sid);
      callback(null);
    } catch (error) { callback(error); }
  }
}

app.disable('x-powered-by');
if (isProduction) app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      imgSrc: ["'self'", 'https:', 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", 'data:', 'https://fonts.gstatic.com'],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(express.json({ limit: '20kb' }));
app.use(session({
  name: 'vicecity.sid',
  secret: SESSION_SECRET,
  store: new SQLiteSessionStore(db),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProduction,
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));
app.use(express.static(path.join(__dirname, 'public'), { maxAge: isProduction ? '1h' : 0 }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Слишком много попыток. Попробуйте чуть позже.' } });
const commentLimiter = rateLimit({ windowMs: 60 * 1000, limit: 8, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Слишком часто. Дайте комментариям немного остыть.' } });

function publicUser(user) {
  return user ? { id: user.id, username: user.username } : null;
}
function getCurrentUser(req) {
  if (!req.session.userId) return null;
  return db.prepare('SELECT id, username FROM users WHERE id = ?').get(req.session.userId) || null;
}
function validHttpUrl(value) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch { return false; }
}
function cleanText(value, maxLength) {
  return typeof value === 'string' ? value.trim().slice(0, maxLength) : '';
}
function regenerateSession(req) {
  return new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()));
}

app.get('/api/auth/me', (req, res) => res.json({ user: publicUser(getCurrentUser(req)) }));

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const username = cleanText(req.body?.username, 20);
    const email = cleanText(req.body?.email, 254).toLowerCase();
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!/^[\p{L}\p{N}_-]{3,20}$/u.test(username)) {
      return res.status(400).json({ error: 'Никнейм: от 3 до 20 букв, цифр, _ или -.' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Проверьте адрес электронной почты.' });
    }
    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({ error: 'Пароль должен содержать от 8 до 72 символов.' });
    }
    const existing = db.prepare('SELECT id FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE').get(username, email);
    if (existing) return res.status(409).json({ error: 'Такой никнейм или email уже используется.' });
    const passwordHash = await bcrypt.hash(password, 12);
    const result = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)').run(username, email, passwordHash);
    await regenerateSession(req);
    req.session.userId = Number(result.lastInsertRowid);
    res.status(201).json({ user: { id: Number(result.lastInsertRowid), username } });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'Такой никнейм или email уже используется.' });
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Не удалось создать аккаунт. Попробуйте ещё раз.' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const identity = cleanText(req.body?.identity, 254);
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const user = db.prepare('SELECT id, username, password_hash FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE').get(identity, identity);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Неверный логин или пароль.' });
    }
    await regenerateSession(req);
    req.session.userId = user.id;
    res.json({ user: publicUser(user) });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Не удалось войти. Попробуйте ещё раз.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(error => {
    if (error) return res.status(500).json({ error: 'Не удалось выйти из аккаунта.' });
    res.clearCookie('vicecity.sid', { httpOnly: true, sameSite: 'lax', secure: isProduction });
    res.json({ ok: true });
  });
});

const parser = new Parser({
  timeout: 10000,
  headers: { 'User-Agent': 'ViceCityGamingNews/1.0 (+RSS reader)' },
  customFields: { item: ['media:content', 'media:thumbnail', 'content:encoded', 'image'] }
});
const FEEDS = [
  { name: 'Google News · RU', url: 'https://news.google.com/rss/search?q=%D0%B8%D0%B3%D1%80%D0%BE%D0%B2%D1%8B%D0%B5%20%D0%BD%D0%BE%D0%B2%D0%BE%D1%81%D1%82%D0%B8%20OR%20%D0%B2%D0%B8%D0%B4%D0%B5%D0%BE%D0%B8%D0%B3%D1%80%D1%8B&hl=ru&gl=RU&ceid=RU:ru' },
  { name: 'IGN', url: 'https://feeds.feedburner.com/ign/news' },
  { name: 'PC Gamer', url: 'https://www.pcgamer.com/rss/' },
  { name: 'GameSpot', url: 'https://www.gamespot.com/feeds/news/' },
  { name: 'Eurogamer', url: 'https://www.eurogamer.net/?format=rss&type=news' }
];
let newsCache = { at: 0, items: [] };
const CACHE_TTL = 5 * 60 * 1000;

function stripHtml(input = '') {
  return String(input)
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/\s+/g, ' ')
    .trim();
}
function findImage(item) {
  const candidates = [
    item.enclosure?.url,
    item.image?.url,
    item['media:content']?.url,
    item['media:content']?.$?.url,
    Array.isArray(item['media:content']) ? item['media:content'][0]?.$?.url : null,
    item['media:thumbnail']?.url,
    item['media:thumbnail']?.$?.url,
    Array.isArray(item['media:thumbnail']) ? item['media:thumbnail'][0]?.$?.url : null
  ];
  const html = item['content:encoded'] || item.content || item.description || '';
  const match = String(html).match(/<img[^>]+src=["']([^"']+)["']/i);
  candidates.push(match?.[1]);
  return candidates.find(value => typeof value === 'string' && /^https:\/\//i.test(value)) || null;
}
function categorize(text) {
  const t = text.toLowerCase();
  if (/gta\s?(?:6|vi)|grand theft auto|rockstar games/.test(t)) return 'GTA VI';
  if (/playstation|\bps5\b|\bps4\b|sony\b/.test(t)) return 'PlayStation';
  if (/xbox|xbox series|microsoft gaming/.test(t)) return 'Xbox';
  if (/nintendo|switch 2|\bswitch\b/.test(t)) return 'Nintendo';
  if (/pc gaming|steam|geforce|amd|\bpc\b|windows/.test(t)) return 'PC';
  return 'Индустрия';
}
async function fetchFeed(feed) {
  try {
    const response = await fetch(feed.url, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; ViceCityGamingNews/1.0)', 'Accept': 'application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.8' },
      signal: AbortSignal.timeout(12000)
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const xml = await response.text();
    const parsed = await parser.parseString(xml);
    return (parsed.items || []).map(item => {
      const title = stripHtml(item.title || 'Без названия');
      const url = item.link || item.guid || '';
      const description = stripHtml(item.contentSnippet || item.summary || item.description || item['content:encoded'] || '');
      const date = item.isoDate || item.pubDate || item.published || null;
      return {
        title,
        url,
        description: description.slice(0, 360),
        image: findImage(item),
        source: feed.name,
        published: date && !Number.isNaN(new Date(date).getTime()) ? new Date(date).toISOString() : null,
        category: categorize(`${title} ${description}`)
      };
    }).filter(item => item.url && validHttpUrl(item.url));
  } catch (error) {
    console.warn(`RSS source unavailable (${feed.name}): ${error.message}`);
    return [];
  }
}
async function getNews(force = false) {
  if (!force && newsCache.items.length && Date.now() - newsCache.at < CACHE_TTL) return newsCache.items;
  const batches = await Promise.all(FEEDS.map(fetchFeed));
  const seen = new Set();
  const items = batches.flat().filter(item => {
    const key = item.url.replace(/\/$/, '').toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort((a, b) => new Date(b.published || 0) - new Date(a.published || 0));
  if (items.length) newsCache = { at: Date.now(), items };
  return newsCache.items;
}

app.get('/api/news', async (req, res) => {
  try {
    const items = await getNews(req.query.refresh === '1');
    res.set('Cache-Control', 'no-store');
    res.json({ items, updatedAt: newsCache.at ? new Date(newsCache.at).toISOString() : null, sources: FEEDS.map(feed => feed.name) });
  } catch (error) {
    console.error('News error:', error);
    res.status(502).json({ error: 'Не получилось загрузить новости. Попробуйте обновить страницу.' });
  }
});

app.get('/api/comments', (req, res) => {
  const articleUrl = cleanText(req.query.url, 2048);
  if (!validHttpUrl(articleUrl)) return res.status(400).json({ error: 'Некорректная ссылка на новость.' });
  const comments = db.prepare(`
    SELECT comments.id, comments.body, comments.created_at AS createdAt, users.id AS userId, users.username
    FROM comments JOIN users ON users.id = comments.user_id
    WHERE comments.article_url = ? ORDER BY comments.id DESC LIMIT 100
  `).all(articleUrl);
  res.json({ comments, currentUserId: req.session.userId || null });
});

app.post('/api/comments', commentLimiter, (req, res) => {
  const user = getCurrentUser(req);
  if (!user) return res.status(401).json({ error: 'Войдите в аккаунт, чтобы оставить комментарий.' });
  const articleUrl = cleanText(req.body?.articleUrl, 2048);
  const articleTitle = cleanText(req.body?.articleTitle, 300) || 'Игровая новость';
  const body = cleanText(req.body?.body, 1000);
  if (!validHttpUrl(articleUrl)) return res.status(400).json({ error: 'Некорректная ссылка на новость.' });
  if (body.length < 2) return res.status(400).json({ error: 'Комментарий слишком короткий.' });
  const result = db.prepare('INSERT INTO comments (article_url, article_title, user_id, body) VALUES (?, ?, ?, ?)').run(articleUrl, articleTitle, user.id, body);
  const comment = db.prepare(`SELECT comments.id, comments.body, comments.created_at AS createdAt, users.id AS userId, users.username FROM comments JOIN users ON users.id = comments.user_id WHERE comments.id = ?`).get(result.lastInsertRowid);
  res.status(201).json({ comment });
});

app.delete('/api/comments/:id', (req, res) => {
  const user = getCurrentUser(req);
  if (!user) return res.status(401).json({ error: 'Войдите в аккаунт.' });
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'Некорректный комментарий.' });
  const result = db.prepare('DELETE FROM comments WHERE id = ? AND user_id = ?').run(id, user.id);
  if (!result.changes) return res.status(404).json({ error: 'Комментарий не найден или принадлежит другому пользователю.' });
  res.json({ ok: true });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => {
  console.log(`Vice City Gaming Portal запущен: http://localhost:${PORT}`);
  if (SESSION_SECRET === 'local-development-secret-change-me' && isProduction) {
    console.warn('ВНИМАНИЕ: задайте собственный SESSION_SECRET в production.');
  }
});
