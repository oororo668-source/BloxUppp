const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { createClient } = require('@libsql/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'bloxup-default-secret-12345';
const ADMIN_NICK = '666';
const ADMIN_PASS = '333777228';
const BOT_TOKEN = process.env.BOT_TOKEN || '';
const ADMIN_TELEGRAM_ID = process.env.ADMIN_TELEGRAM_ID || '';

const db = createClient({
  url: process.env.TURSO_DATABASE_URL || 'file:local.db',
  authToken: process.env.TURSO_AUTH_TOKEN || undefined,
});

async function initDb() {
  try {
    await db.execute(`CREATE TABLE IF NOT EXISTS users (nick TEXT PRIMARY KEY, password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member', balance INTEGER NOT NULL DEFAULT 0, telegram_id TEXT, created_at INTEGER NOT NULL, is_banned INTEGER NOT NULL DEFAULT 0, is_removed_from_leaderboard INTEGER NOT NULL DEFAULT 0)`);
    await db.execute(`CREATE TABLE IF NOT EXISTS chats (id TEXT PRIMARY KEY, nick TEXT NOT NULL, amount INTEGER NOT NULL, type TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`);
    await db.execute(`CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, chat_id TEXT NOT NULL, sender TEXT NOT NULL, sender_role TEXT NOT NULL, text TEXT NOT NULL, created_at INTEGER NOT NULL)`);
    await db.execute(`CREATE TABLE IF NOT EXISTS stats (nick TEXT PRIMARY KEY, won INTEGER NOT NULL DEFAULT 0, lost INTEGER NOT NULL DEFAULT 0, spins INTEGER NOT NULL DEFAULT 0)`);
    await db.execute(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
    
    // Добавляем колонки, если таблица была создана раньше
    try { await db.execute(`ALTER TABLE users ADD COLUMN is_banned INTEGER NOT NULL DEFAULT 0`); } catch(e){}
    try { await db.execute(`ALTER TABLE users ADD COLUMN is_removed_from_leaderboard INTEGER NOT NULL DEFAULT 0`); } catch(e){}
    
    await db.execute(`INSERT OR IGNORE INTO settings (key, value) VALUES ('abuse_all_win', 'false'), ('ban_all', 'false')`);
    
    console.log('Tables initialized');
  } catch (e) {
    console.error('Error creating tables:', e);
  }

  const adm = await db.execute({ sql: 'SELECT nick FROM users WHERE nick=?', args: [ADMIN_NICK] });
  if (adm.rows.length === 0) {
    await db.execute({
      sql: 'INSERT INTO users (nick,password,role,balance,created_at) VALUES (?,?,?,?,?)',
      args: [ADMIN_NICK, bcrypt.hashSync(ADMIN_PASS, 10), 'admin', 0, Date.now()],
    });
  }
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

async function notifyAdmin(text) {
  if (!BOT_TOKEN || !ADMIN_TELEGRAM_ID) return;
  try {
    await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: ADMIN_TELEGRAM_ID, text, parse_mode: 'HTML' }),
    });
  } catch (e) { console.error('tg notify', e.message); }
}

app.post('/api/register', async (req, res) => {
  try {
    const { nick, password, telegram_id } = req.body || {};
    if (!nick || !password) return res.status(400).json({ error: 'Заполни ник и пароль' });
    
    const settings = await db.execute('SELECT * FROM settings');
    const isBanAll = settings.rows.find(s => s.key === 'ban_all')?.value === 'true';
    if (isBanAll) return res.status(403).json({ error: 'Регистрация временно закрыта (Бан всех)' });

    if (nick.length < 3) return res.status(400).json({ error: 'Ник от 3 символов' });
    const exist = await db.execute({ sql: 'SELECT nick FROM users WHERE nick=?', args: [nick] });
    if (exist.rows.length) return res.status(400).json({ error: 'Ник занят' });
    
    await db.execute({
      sql: 'INSERT INTO users (nick,password,role,balance,telegram_id,created_at,is_banned,is_removed_from_leaderboard) VALUES (?,?,?,?,?,?,0,0)',
      args: [nick, bcrypt.hashSync(password, 10), 'member', 0, telegram_id || null, Date.now()],
    });
    const token = jwt.sign({ nick, role: 'member' }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, nick, role: 'member', balance: 0 });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { nick, password, telegram_id } = req.body || {};
    const r = await db.execute({ sql: 'SELECT * FROM users WHERE nick=?', args: [nick] });
    const user = r.rows[0];
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: 'Неверный ник или пароль' });
    
    if (user.is_banned) return res.status(403).json({ error: 'Вы забанены' });
    
    if (telegram_id && !user.telegram_id) {
      await db.execute({ sql: 'UPDATE users SET telegram_id=? WHERE nick=?', args: [String(telegram_id), nick] });
    }
    
    const settings = await db.execute('SELECT * FROM settings');
    const isBanAll = settings.rows.find(s => s.key === 'ban_all')?.value === 'true';
    if (isBanAll && user.role !== 'admin') return res.status(403).json({ error: 'Сервер закрыт для входа (Бан всех)' });

    const token = jwt.sign({ nick: user.nick, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, nick: user.nick, role: user.role, balance: user.balance });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/me', async (req, res) => {
  try {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    const { nick } = jwt.verify(token, JWT_SECRET);
    const r = await db.execute({ sql: 'SELECT nick,role,balance FROM users WHERE nick=?', args: [nick] });
    if (!r.rows[0]) return res.status(404).json({ error: 'Не найден' });
    res.json(r.rows[0]);
  } catch { res.status(401).json({ error: 'Bad token' }); }
});

app.get('/api/leaderboard', async (req, res) => {
  const r = await db.execute({ 
    sql: `SELECT s.nick, s.won, s.spins FROM stats s 
          JOIN users u ON u.nick = s.nick 
          WHERE s.won > 0 AND u.is_removed_from_leaderboard = 0 
          ORDER BY s.won DESC LIMIT 20` 
  });
  res.json(r.rows);
});

io.use((socket, next) => {
  try {
    const payload = jwt.verify(socket.handshake.auth?.token, JWT_SECRET);
    socket.user = payload;
    next();
  } catch { next(new Error('unauthorized')); }
});

async function broadcastChatList() {
  const r = await db.execute({
    sql: `SELECT c.*, (SELECT COUNT(*) FROM messages m WHERE m.chat_id=c.id AND m.sender_role='player' AND m.created_at > IFNULL(c.updated_at,0)) AS unread FROM chats c ORDER BY c.updated_at DESC`,
  });
  io.to('admins').emit('chatList', r.rows);
}

async function sendMessage(chatId, sender, senderRole, text) {
  const r = await db.execute({
    sql: 'INSERT INTO messages (chat_id,sender,sender_role,text,created_at) VALUES (?,?,?,?,?)',
    args: [chatId, sender, senderRole, text, Date.now()],
  });
  await db.execute({ sql: 'UPDATE chats SET updated_at=? WHERE id=?', args: [Date.now(), chatId] });
  const msg = { id: Number(r.lastInsertRowid), chat_id: chatId, sender, sender_role: senderRole, text, created_at: Date.now() };
  io.to('chat_' + chatId).emit('message', msg);
  broadcastChatList();
}

io.on('connection', (socket) => {
  const { nick, role } = socket.user;
  if (role === 'admin') socket.join('admins');

  socket.on('openChat', async (chatId) => {
    socket.join('chat_' + chatId);
    const r = await db.execute({ sql: 'SELECT * FROM messages WHERE chat_id=? ORDER BY created_at', args: [chatId] });
    socket.emit('history', { chatId, messages: r.rows });
  });

  socket.on('updateBalance', async ({ newBalance }) => {
    try {
      await db.execute({ sql: 'UPDATE users SET balance=? WHERE nick=?', args: [newBalance, nick] });
    } catch (e) { console.error('updateBalance', e); }
  });

  socket.on('createChat', async ({ amount, type, firstMessage }, ack) => {
    if (type === 'withdraw') {
      const userRes = await db.execute({ sql: 'SELECT balance FROM users WHERE nick=?', args: [nick] });
      const currentBalance = userRes.rows[0]?.balance || 0;
      if (currentBalance < amount) return socket.emit('errorMsg', 'Недостаточно средств для вывода');
      await db.execute({ sql: 'UPDATE users SET balance = balance - ? WHERE nick=?', args: [amount, nick] });
    }

    const id = 'chat_' + Date.now() + '_' + Math.floor(Math.random() * 1000);
    await db.execute({
      sql: 'INSERT INTO chats (id,nick,amount,type,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?)',
      args: [id, nick, amount, type, 'pending', Date.now(), Date.now()],
    });
    socket.join('chat_' + id);
    await sendMessage(id, nick, 'player', firstMessage);
    const sysText = type === 'withdraw'
      ? 'Скиньте геймпасс на сумму вывода — админ оплатит в течение 7 дней.'
      : 'Купи геймпасс и напиши "Оплатил". Админ проверит и начислит.';
    await sendMessage(id, 'admin', 'system', sysText);
    if (ack) ack({ chatId: id });
    broadcastChatList();
    notifyAdmin(`🔔 <b>Новая заявка</b>\nТип: ${type}\nИгрок: ${nick}\nСумма: ${amount} R$`);
  });

  socket.on('sendMessage', async ({ chatId, text }) => {
    if (!text?.trim()) return;
    await sendMessage(chatId, nick, role === 'admin' ? 'admin' : 'player', text.trim());
    if (role !== 'admin') notifyAdmin(`💬 <b>Сообщение</b>\nОт: ${nick}\n\n${text.trim()}`);
  });

  socket.on('adminAction', async ({ chatId, action }) => {
    if (role !== 'admin') return;
    const r = await db.execute({ sql: 'SELECT * FROM chats WHERE id=?', args: [chatId] });
    const chat = r.rows[0];
    if (!chat || chat.status !== 'pending') return;
    if (action === 'credit') {
      if (chat.type !== 'withdraw') {
        await db.execute({ sql: 'UPDATE users SET balance=balance+? WHERE nick=?', args: [chat.amount, chat.nick] });
      }
      await db.execute({ sql: 'UPDATE chats SET status=? WHERE id=?', args: ['accepted', chatId] });
      await sendMessage(chatId, 'admin', 'success', `✅ Начислено ${chat.amount} R$`);
    } else if (action === 'payout') {
      await db.execute({ sql: 'UPDATE chats SET status=? WHERE id=?', args: ['paid', chatId] });
      await sendMessage(chatId, 'admin', 'success', `✅ Вывод ${chat.amount} R$ оплачен`);
    } else if (action === 'reject') {
      if (chat.type === 'withdraw') {
        await db.execute({ sql: 'UPDATE users SET balance=balance+? WHERE nick=?', args: [chat.amount, chat.nick] });
      }
      await db.execute({ sql: 'UPDATE chats SET status=? WHERE id=?', args: ['rejected', chatId] });
      await sendMessage(chatId, 'admin', 'danger', '❌ Заявка отклонена');
    }
    broadcastChatList();
  });

  socket.on('saveStats', async ({ won, lost, spins }) => {
    await db.execute({
      sql: `INSERT INTO stats (nick,won,lost,spins) VALUES (?,?,?,?) ON CONFLICT(nick) DO UPDATE SET won=won+?, lost=lost+?, spins=spins+?`,
      args: [nick, won, lost, spins, won, lost, spins],
    });
  });

  // НОВЫЕ СОБЫТИЯ ДЛЯ АДМИНКИ
  socket.on('getAdminData', async (ack) => {
    if (role !== 'admin') return;
    const users = await db.execute('SELECT nick, balance, is_banned FROM users WHERE role != "admin"');
    const settings = await db.execute('SELECT * FROM settings');
    const sObj = {};
    settings.rows.forEach(r => sObj[r.key] = r.value);
    if (ack) ack({ users: users.rows, settings: sObj });
  });

  socket.on('adminCredit', async ({ targetNick, amount }) => {
    if (role !== 'admin') return;
    await db.execute({ sql: 'UPDATE users SET balance = balance + ? WHERE nick=?', args: [amount, targetNick] });
  });

  socket.on('adminDebit', async ({ targetNick, amount }) => {
    if (role !== 'admin') return;
    await db.execute({ sql: 'UPDATE users SET balance = balance - ? WHERE nick=?', args: [amount, targetNick] });
  });

  socket.on('adminBan', async ({ targetNick, ban }) => {
    if (role !== 'admin') return;
    await db.execute({ sql: 'UPDATE users SET is_banned = ? WHERE nick=?', args: [ban ? 1 : 0, targetNick] });
  });

  socket.on('adminRemoveLeaderboard', async ({ targetNick, remove }) => {
    if (role !== 'admin') return;
    await db.execute({ sql: 'UPDATE users SET is_removed_from_leaderboard = ? WHERE nick=?', args: [remove ? 1 : 0, targetNick] });
  });

  socket.on('adminUpdateSettings', async ({ key, value }) => {
    if (role !== 'admin') return;
    await db.execute({ sql: 'UPDATE settings SET value=? WHERE key=?', args: [value, key] });
    if (key === 'abuse_all_win' || key === 'ban_all') {
      io.emit('settingsUpdated', { key, value });
    }
  });

  socket.on('getGameSettings', async (ack) => {
    const settings = await db.execute('SELECT * FROM settings');
    const sObj = {};
    settings.rows.forEach(r => sObj[r.key] = r.value);
    if (ack) ack(sObj);
  });
});

initDb().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log('BloxUp server listening on port ' + PORT);
  });
}).catch(err => {
  console.error('DB init error:', err);
  process.exit(1);
});
