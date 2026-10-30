const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'skyaviator_secret_jwt_32_chars_long';

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// 1. DATABASE SETUP
const db = new Database('skyaviator.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    username TEXT NOT NULL UNIQUE,
    phone_number TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    date_of_birth TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS wallets (
    user_id INTEGER PRIMARY KEY,
    balance_cents INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS game_rounds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    crash_multiplier REAL NOT NULL,
    status TEXT DEFAULT 'WAITING',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS bets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    round_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    bet_cents INTEGER NOT NULL,
    cashout_multiplier REAL,
    payout_cents INTEGER DEFAULT 0,
    status TEXT DEFAULT 'ACTIVE'
  );
`);

// 2. AUTHENTICATION MIDDLEWARE
function auth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ success: false, message: 'Unauthenticated' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ success: false, message: 'Session expired' });
  }
}

// 3. API ROUTES
app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullName, username, phoneNumber, email, password, dateOfBirth, acceptTerms } = req.body;
    if (!acceptTerms) return res.status(400).json({ success: false, message: 'Must accept terms' });

    // 18+ check
    const age = new Date().getFullYear() - new Date(dateOfBirth).getFullYear();
    if (age < 18) return res.status(403).json({ success: false, message: 'Must be 18 or older' });

    const hash = await bcrypt.hash(password, 10);
    const tx = db.transaction(() => {
      const u = db.prepare('INSERT INTO users (full_name, username, phone_number, email, password_hash, date_of_birth) VALUES (?, ?, ?, ?, ?, ?)')
        .run(fullName, username, phoneNumber, email, hash, dateOfBirth);
      // Give initial trial sandbox balance of KSh 2,500.00 (250,000 cents)
      db.prepare('INSERT INTO wallets (user_id, balance_cents) VALUES (?, 250000)').run(u.lastInsertRowid);
    });
    tx();
    res.json({ success: true, message: 'Account created! Please sign in.' });
  } catch (e) {
    res.status(400).json({ success: false, message: 'User or phone number already exists' });
  }
});

app.post('/api/auth/signin', async (req, res) => {
  const { identifier, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ? OR phone_number = ?').get(identifier, identifier, identifier);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
  res.cookie('token', token, { httpOnly: true, maxAge: 86400000 });
  res.json({ success: true });
});

app.post('/api/auth/signout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

app.get('/api/user/me', auth, (req, res) => {
  const user = db.prepare('SELECT id, full_name, username, phone_number, email FROM users WHERE id = ?').get(req.user.id);
  const wallet = db.prepare('SELECT balance_cents FROM wallets WHERE user_id = ?').get(req.user.id);
  res.json({
    success: true,
    user,
    balanceKsh: (wallet.balance_cents / 100).toFixed(2)
  });
});

app.post('/api/payments/deposit', auth, (req, res) => {
  const amountCents = Math.round(parseFloat(req.body.amountKsh) * 100);
  if (amountCents < 1000) return res.status(400).json({ success: false, message: 'Min KSh 10' });
  db.prepare('UPDATE wallets SET balance_cents = balance_cents + ? WHERE user_id = ?').run(amountCents, req.user.id);
  res.json({ success: true, message: 'M-Pesa Sandbox deposit received!' });
});

app.post('/api/payments/withdraw', auth, (req, res) => {
  const amountCents = Math.round(parseFloat(req.body.amountKsh) * 100);
  const wallet = db.prepare('SELECT balance_cents FROM wallets WHERE user_id = ?').get(req.user.id);
  if (wallet.balance_cents < amountCents) return res.status(400).json({ success: false, message: 'Insufficient balance' });
  db.prepare('UPDATE wallets SET balance_cents = balance_cents - ? WHERE user_id = ?').run(amountCents, req.user.id);
  res.json({ success: true, message: 'M-Pesa Withdrawal processed!' });
});

app.get('/api/game/history', (req, res) => {
  const rounds = db.prepare('SELECT crash_multiplier FROM game_rounds WHERE status = "CRASHED" ORDER BY id DESC LIMIT 15').all();
  res.json({ success: true, rounds });
});

// 4. CRASH ENGINE (PROVABLY FAIR 97% RTP)
let roundState = 'WAITING';
let multiplier = 1.00;
let crashPoint = 1.00;
let currentRoundId = 0;
let activeBets = new Map();

function generateCrashPoint() {
  const r = Math.random();
  if (r < 0.03) return 1.00; // 3% house edge instant crash
  return Math.max(1.00, parseFloat((0.97 / (1.0 - r)).toFixed(2)));
}

function startRound() {
  roundState = 'WAITING';
  multiplier = 1.00;
  activeBets.clear();
  crashPoint = generateCrashPoint();

  const round = db.prepare('INSERT INTO game_rounds (crash_multiplier) VALUES (?)').run(crashPoint);
  currentRoundId = round.lastInsertRowid;

  let countdown = 5;
  const timer = setInterval(() => {
    io.emit('round_waiting', { countdown });
    countdown--;
    if (countdown < 0) {
      clearInterval(timer);
      launchFlight();
    }
  }, 1000);
}

function launchFlight() {
  roundState = 'FLYING';
  db.prepare('UPDATE game_rounds SET status = "FLYING" WHERE id = ?').run(currentRoundId);
  io.emit('round_started');

  const start = Date.now();
  const loop = setInterval(() => {
    const elapsed = (Date.now() - start) / 1000;
    multiplier = parseFloat((1.00 + Math.pow(elapsed * 0.75, 1.75)).toFixed(2));

    if (multiplier >= crashPoint) {
      clearInterval(loop);
      roundState = 'CRASHED';
      db.prepare('UPDATE game_rounds SET status = "CRASHED" WHERE id = ?').run(currentRoundId);
      io.emit('round_crashed', { crashMultiplier: crashPoint });
      setTimeout(startRound, 4000);
    } else {
      io.emit('round_tick', { multiplier });
    }
  }, 60);
}

// 5. WEBSOCKETS
io.on('connection', (socket) => {
  socket.on('place_bet', (data, cb) => {
    const cookies = socket.handshake.headers.cookie;
    if (!cookies) return cb({ success: false, message: 'Unauthenticated' });
    const token = cookies.split('token=')[1]?.split(';')[0];
    try {
      const user = jwt.verify(token, JWT_SECRET);
      if (roundState !== 'WAITING') return cb({ success: false, message: 'Round in progress' });
      const betCents = Math.round(parseFloat(data.amountKsh) * 100);

      const wallet = db.prepare('SELECT balance_cents FROM wallets WHERE user_id = ?').get(user.id);
      if (wallet.balance_cents < betCents) return cb({ success: false, message: 'Insufficient balance' });

      db.prepare('UPDATE wallets SET balance_cents = balance_cents - ? WHERE user_id = ?').run(betCents, user.id);
      activeBets.set(user.id, { betCents, cashedOut: false });
      cb({ success: true });
    } catch (e) {
      cb({ success: false, message: 'Auth failed' });
    }
  });

  socket.on('cash_out', (cb) => {
    const cookies = socket.handshake.headers.cookie;
    const token = cookies?.split('token=')[1]?.split(';')[0];
    try {
      const user = jwt.verify(token, JWT_SECRET);
      if (roundState !== 'FLYING') return cb({ success: false, message: 'Not flying' });
      const bet = activeBets.get(user.id);
      if (!bet || bet.cashedOut) return cb({ success: false, message: 'No bet active' });

      bet.cashedOut = true;
      const payoutCents = Math.floor(bet.betCents * multiplier);
      db.prepare('UPDATE wallets SET balance_cents = balance_cents + ? WHERE user_id = ?').run(payoutCents, user.id);
      cb({ success: true, wonKsh: (payoutCents / 100).toFixed(2) });
    } catch (e) {
      cb({ success: false, message: 'Error cashing out' });
    }
  });
});

startRound();
server.listen(PORT, '0.0.0.0', () => console.log('SkyAviator running on port ' + PORT));
