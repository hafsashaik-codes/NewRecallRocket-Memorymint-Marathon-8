const express = require("express");
const session = require("express-session");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const db = new Database("recallrocket.db");
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS decks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cards (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  deck_id INTEGER NOT NULL,
  question TEXT NOT NULL,
  answer TEXT NOT NULL,
  interval INTEGER DEFAULT 0,
  repetitions INTEGER DEFAULT 0,
  ease_factor REAL DEFAULT 2.5,
  due_at TEXT DEFAULT CURRENT_TIMESTAMP,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(deck_id) REFERENCES decks(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  card_id INTEGER NOT NULL,
  grade INTEGER NOT NULL,
  reviewed_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(card_id) REFERENCES cards(id)
);
`);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 24 * 60 * 60 * 1000
  }
}));

app.use(express.static(path.join(__dirname)));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Please log in first." });
  }
  next();
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, original] = stored.split(":");
  const hash = crypto.scryptSync(password, salt, 64);
  const originalBuffer = Buffer.from(original, "hex");
  return originalBuffer.length === hash.length &&
    crypto.timingSafeEqual(hash, originalBuffer);
}

function getStreak(userId) {
  const rows = db.prepare(`
    SELECT DISTINCT date(reviewed_at) AS day
    FROM reviews
    WHERE user_id = ?
    ORDER BY day DESC
  `).all(userId);

  if (!rows.length) return 0;

  const days = new Set(rows.map(r => r.day));
  const today = new Date().toISOString().slice(0, 10);
  const yesterday = new Date(Date.now() - 86400000)
    .toISOString().slice(0, 10);

  let current = days.has(today) ? today : yesterday;
  if (!days.has(current)) return 0;

  let streak = 0;
  while (days.has(current)) {
    streak++;
    const date = new Date(current + "T00:00:00Z");
    date.setUTCDate(date.getUTCDate() - 1);
    current = date.toISOString().slice(0, 10);
  }
  return streak;
}

function getNextReview(card, grade) {
  let repetitions = card.repetitions;
  let interval = card.interval;
  let ease = card.ease_factor;

  if (grade < 3) {
    repetitions = 0;
    interval = 1;
  } else {
    if (repetitions === 0) interval = 1;
    else if (repetitions === 1) interval = 6;
    else interval = Math.round(interval * ease);

    repetitions++;
  }

  ease = Math.max(
    1.3,
    ease + (0.1 - (5 - grade) * (0.08 + (5 - grade) * 0.02))
  );

  const due = new Date();
  due.setUTCDate(due.getUTCDate() + interval);

  return {
    repetitions,
    interval,
    ease,
    dueAt: due.toISOString()
  };
}

function createSampleDeck(userId) {
  const deck = db.prepare(
    "INSERT INTO decks (user_id, name) VALUES (?, ?)"
  ).run(userId, "Computer Science Basics");

  const cards = [
    ["What is an algorithm?", "A finite sequence of steps used to solve a problem."],
    ["What is time complexity?", "A measure of how an algorithm's running time grows with input size."],
    ["What is Quick Sort?", "A divide-and-conquer sorting algorithm using a pivot."],
    ["What is a database?", "An organized collection of structured information."],
    ["What is HTML?", "The markup language used to structure web pages."],
    ["What is CSS?", "A stylesheet language used to design web pages."],
    ["What is JavaScript?", "A programming language used to create interactive web experiences."],
    ["What is a stack?", "A LIFO data structure: Last In, First Out."],
    ["What is a queue?", "A FIFO data structure: First In, First Out."],
    ["What is an API?", "An interface that allows software systems to communicate."]
  ];

  const insert = db.prepare(`
    INSERT INTO cards (deck_id, question, answer)
    VALUES (?, ?, ?)
  `);

  const transaction = db.transaction(items => {
    for (const [q, a] of items) insert.run(deck.lastInsertRowid, q, a);
  });

  transaction(cards);
}

app.post("/api/register", authLimiter, (req, res) => {
  try {
    const { name, username, password } = req.body;

    if (!name || !username || !password ||
        name.length > 50 || username.length > 30 ||
        !/^[a-zA-Z0-9_]+$/.test(username) ||
        password.length < 8 || password.length > 100) {
      return res.status(400).json({
        error: "Enter a name, valid username and password (8-100 characters)."
      });
    }

    const result = db.prepare(`
      INSERT INTO users (name, username, password_hash)
      VALUES (?, ?, ?)
    `).run(name.trim(), username.toLowerCase(), hashPassword(password));

    createSampleDeck(result.lastInsertRowid);
    req.session.userId = Number(result.lastInsertRowid);

    res.status(201).json({
      message: "Account created successfully.",
      user: { id: Number(result.lastInsertRowid), name: name.trim() }
    });
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "Username already exists." });
    }
    console.error(error);
    res.status(500).json({ error: "Could not create account." });
  }
});

app.post("/api/login", authLimiter, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Enter username and password." });
  }

  const user = db.prepare(
    "SELECT * FROM users WHERE username = ?"
  ).get(username.toLowerCase());

  if (!user || !verifyPassword(password, user.password_hash)) {
    return res.status(401).json({ error: "Incorrect username or password." });
  }

  req.session.userId = user.id;
  res.json({ message: "Welcome back!", user: { id: user.id, name: user.name } });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ message: "Logged out." });
  });
});

app.get("/api/me", requireLogin, (req, res) => {
  const user = db.prepare(
    "SELECT id, name, username FROM users WHERE id = ?"
  ).get(req.session.userId);
  res.json({ user });
});

app.get("/api/decks", requireLogin, (req, res) => {
  const decks = db.prepare(`
    SELECT d.id, d.name, COUNT(c.id) AS card_count
    FROM decks d
    LEFT JOIN cards c ON c.deck_id = d.id
    WHERE d.user_id = ?
    GROUP BY d.id
    ORDER BY d.id DESC
  `).all(req.session.userId);

  res.json(decks);
});

app.post("/api/decks", requireLogin, (req, res) => {
  const name = String(req.body.name || "").trim();
  if (!name || name.length > 60) {
    return res.status(400).json({ error: "Deck name must be 1-60 characters." });
  }

  const result = db.prepare(
    "INSERT INTO decks (user_id, name) VALUES (?, ?)"
  ).run(req.session.userId, name);

  res.status(201).json({
    id: Number(result.lastInsertRowid),
    name,
    card_count: 0
  });
});

function ownedDeck(deckId, userId) {
  return db.prepare(
    "SELECT id FROM decks WHERE id = ? AND user_id = ?"
  ).get(deckId, userId);
}

app.post("/api/decks/:id/cards", requireLogin, (req, res) => {
  const deckId = Number(req.params.id);
  const { question, answer } = req.body;

  if (!ownedDeck(deckId, req.session.userId)) {
    return res.status(404).json({ error: "Deck not found." });
  }

  if (typeof question !== "string" || typeof answer !== "string" ||
      !question.trim() || !answer.trim() ||
      question.length > 1000 || answer.length > 3000) {
    return res.status(400).json({ error: "Enter a valid question and answer." });
  }

  const result = db.prepare(`
    INSERT INTO cards (deck_id, question, answer)
    VALUES (?, ?, ?)
  `).run(deckId, question.trim(), answer.trim());

  res.status(201).json({ id: Number(result.lastInsertRowid) });
});

app.get("/api/due", requireLogin, (req, res) => {
  const userId = req.session.userId;
  const deckId = req.query.deckId ? Number(req.query.deckId) : null;

  let cards;
  if (deckId) {
    if (!ownedDeck(deckId, userId)) {
      return res.status(404).json({ error: "Deck not found." });
    }

    cards = db.prepare(`
      SELECT c.id, c.question, c.answer, c.interval, c.repetitions,
             c.ease_factor, c.due_at
      FROM cards c
      JOIN decks d ON d.id = c.deck_id
      WHERE d.user_id = ? AND d.id = ? AND c.due_at <= ?
      ORDER BY c.due_at LIMIT 100
    `).all(userId, deckId, new Date().toISOString());
  } else {
    cards = db.prepare(`
      SELECT c.id, c.question, c.answer, c.interval, c.repetitions,
             c.ease_factor, c.due_at
      FROM cards c
      JOIN decks d ON d.id = c.deck_id
      WHERE d.user_id = ? AND c.due_at <= ?
      ORDER BY c.due_at LIMIT 100
    `).all(userId, new Date().toISOString());
  }

  res.json(cards);
});

app.post("/api/review", requireLogin, (req, res) => {
  const cardId = Number(req.body.cardId);
  const grade = Number(req.body.grade);

  if (!Number.isInteger(cardId) ||
      !Number.isInteger(grade) || grade < 0 || grade > 5) {
    return res.status(400).json({ error: "Invalid card or rating." });
  }

  const card = db.prepare(`
    SELECT c.* FROM cards c
    JOIN decks d ON d.id = c.deck_id
    WHERE c.id = ? AND d.user_id = ?
  `).get(cardId, req.session.userId);

  if (!card) return res.status(404).json({ error: "Card not found." });

  const next = getNextReview(card, grade);

  const transaction = db.transaction(() => {
    db.prepare(`
      UPDATE cards
      SET interval = ?, repetitions = ?, ease_factor = ?, due_at = ?
      WHERE id = ?
    `).run(next.interval, next.repetitions, next.ease, next.dueAt, cardId);

    db.prepare(`
      INSERT INTO reviews (user_id, card_id, grade)
      VALUES (?, ?, ?)
    `).run(req.session.userId, cardId, grade);
  });

  transaction();

  res.json({
    message: "Review saved.",
    nextInterval: next.interval,
    nextReview: next.dueAt,
    streak: getStreak(req.session.userId)
  });
});

app.get("/api/stats", requireLogin, (req, res) => {
  const userId = req.session.userId;

  const totals = db.prepare(`
    SELECT
      (SELECT COUNT(*) FROM decks WHERE user_id = ?) AS decks,
      (SELECT COUNT(*) FROM cards c JOIN decks d ON c.deck_id=d.id
       WHERE d.user_id = ?) AS cards,
      (SELECT COUNT(*) FROM reviews WHERE user_id = ?) AS reviews,
      (SELECT COUNT(*) FROM cards c JOIN decks d ON c.deck_id=d.id
       WHERE d.user_id = ? AND c.due_at <= ?) AS due
  `).get(userId, userId, userId, userId, new Date().toISOString());

  const today = new Date().toISOString().slice(0, 10);
  const todayReviews = db.prepare(`
    SELECT COUNT(*) AS count FROM reviews
    WHERE user_id = ? AND date(reviewed_at) = ?
  `).get(userId, today).count;

  res.json({
    ...totals,
    todayReviews,
    streak: getStreak(userId)
  });
});

app.get("/api/leaderboard", requireLogin, (req, res) => {
  const rows = db.prepare(`
    SELECT u.id, u.name,
      COUNT(r.id) AS reviews,
      COUNT(DISTINCT date(r.reviewed_at)) AS active_days
    FROM users u
    LEFT JOIN reviews r ON r.user_id = u.id
    GROUP BY u.id
    ORDER BY reviews DESC, active_days DESC, u.name ASC
    LIMIT 20
  `).all();

  res.json(rows.map((row, index) => ({
    rank: index + 1,
    name: row.name,
    reviews: row.reviews,
    activeDays: row.active_days,
    streak: getStreak(row.id)
  })));
});

app.post("/api/generate", requireLogin, (req, res) => {
  const deckId = Number(req.body.deckId);
  const notes = String(req.body.notes || "").trim();

  if (!ownedDeck(deckId, req.session.userId)) {
    return res.status(404).json({ error: "Deck not found." });
  }
  if (notes.length < 30 || notes.length > 10000) {
    return res.status(400).json({
      error: "Paste notes between 30 and 10000 characters."
    });
  }

  const sentences = notes.split(/(?<=[.!?])\s+/)
    .map(s => s.trim())
    .filter(s => s.length >= 25);

  const generated = sentences.slice(0, 5).map((sentence, index) => ({
    question: `What is the key point ${index + 1} from these notes?`,
    answer: sentence
  }));

  if (!generated.length) {
    return res.status(400).json({
      error: "Could not find complete sentences. Add more detailed notes."
    });
  }

  const insert = db.prepare(`
    INSERT INTO cards (deck_id, question, answer) VALUES (?, ?, ?)
  `);
  const save = db.transaction(() => {
    for (const item of generated) {
      insert.run(deckId, item.question, item.answer);
    }
  });
  save();

  res.json({
    message: `${generated.length} flashcards created from your notes.`,
    generated
  });
});

app.get("/api/export/:id", requireLogin, (req, res) => {
  const deckId = Number(req.params.id);
  if (!ownedDeck(deckId, req.session.userId)) {
    return res.status(404).json({ error: "Deck not found." });
  }

  const cards = db.prepare(`
    SELECT c.question, c.answer
    FROM cards c JOIN decks d ON c.deck_id = d.id
    WHERE d.id = ? AND d.user_id = ?
  `).all(deckId, req.session.userId);

  const quote = value => `"${String(value).replace(/"/g, '""')}"`;
  const csv = [
    "Question,Answer",
    ...cards.map(c => `${quote(c.question)},${quote(c.answer)}`)
  ].join("\n");

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", 'attachment; filename="recallrocket-deck.csv"');
  res.send("\uFEFF" + csv);
});

app.post("/api/import/:id", requireLogin, (req, res) => {
  const deckId = Number(req.params.id);
  if (!ownedDeck(deckId, req.session.userId)) {
    return res.status(404).json({ error: "Deck not found." });
  }

  const cards = req.body.cards;
  if (!Array.isArray(cards) || cards.length < 1 || cards.length > 200) {
    return res.status(400).json({ error: "Import 1 to 200 cards at a time." });
  }

  const valid = cards.filter(c =>
    typeof c.question === "string" &&
    typeof c.answer === "string" &&
    c.question.trim() && c.answer.trim() &&
    c.question.length <= 1000 && c.answer.length <= 3000
  );

  if (!valid.length) {
    return res.status(400).json({ error: "No valid question-answer pairs found." });
  }

  const insert = db.prepare(`
    INSERT INTO cards (deck_id, question, answer) VALUES (?, ?, ?)
  `);

  const save = db.transaction(() => {
    for (const c of valid) {
      insert.run(deckId, c.question.trim(), c.answer.trim());
    }
  });
  save();

  res.json({ message: `${valid.length} cards imported.` });
});

app.get("/api/decay", requireLogin, (req, res) => {
  const userId = req.session.userId;
  const cards = db.prepare(`
    SELECT c.question, c.interval, c.ease_factor, c.due_at
    FROM cards c JOIN decks d ON c.deck_id = d.id
    WHERE d.user_id = ?
    ORDER BY c.due_at LIMIT 30
  `).all(userId);

  res.json(cards.map(c => ({
    question: c.question,
    interval: c.interval,
    ease: c.ease_factor,
    dueAt: c.due_at,
    retention: Math.round(
      100 * Math.exp(-Math.max(0, c.interval) / 20)
    )
  })));
});

app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).json({ error: "An unexpected server error occurred." });
});

app.listen(PORT, () => {
  console.log(`RecallRocket is running at http://localhost:${PORT}`);
});