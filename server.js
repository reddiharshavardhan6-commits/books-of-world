// server.js — BooksOfWorlds backend.
// Serves the game HTML and the /api/* auth endpoints on http://localhost:3000.

require("dotenv").config();
const path = require("path");
const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise"); // promise-based, so we can use async/await

const app = express();
const PORT = process.env.PORT || 3000;

// ── MySQL connection pool ────────────────────────────────────────────────
const db = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    port: Number(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || "BooksOfWorlds",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Fail loudly at startup if the DB is unreachable, instead of every
// request timing out silently later.
db.getConnection()
    .then((conn) => {
        console.log("MySQL connected successfully!");
        conn.release();
    })
    .catch((err) => {
        console.log("MySQL connection failed:", err.message);
    });

// ── middleware ───────────────────────────────────────────────────────────
app.use(express.json());
app.use(cookieParser());

// Only needed if you ever serve the HTML from a different origin/port
// than this backend (e.g. a separate dev server). Not needed for the
// default setup below, where this same server serves the HTML on :3000.
if (process.env.ALLOWED_ORIGIN) {
    app.use(cors({ origin: process.env.ALLOWED_ORIGIN, credentials: true }));
}

const SALT_ROUNDS = 12;
const TOKEN_TTL = "7d";
const COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

function isValidEmail(s) {
    return typeof s === "string" && /^\S+@\S+\.\S+$/.test(s);
}

function signToken(user) {
    return jwt.sign(
        { id: user.id, username: user.username, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: TOKEN_TTL }
    );
}

function setAuthCookie(res, token) {
    res.cookie("bow_token", token, {
        httpOnly: true,
        sameSite: "lax",
        secure: false, // set true once you're running behind HTTPS
        maxAge: COOKIE_MAX_AGE_MS
    });
}

function requireAuth(req, res, next) {
    const token = req.cookies && req.cookies.bow_token;
    if (!token) return res.status(401).json({ error: "Not logged in." });
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (e) {
        return res.status(401).json({ error: "Session expired or invalid. Please log in again." });
    }
}

// ── POST /api/register ───────────────────────────────────────────────────
app.post("/api/register", async (req, res) => {
    try {
        const username = (req.body.username || "").trim();
        const email = (req.body.email || "").trim().toLowerCase();
        const password = req.body.password || "";

        if (username.length < 3) {
            return res.status(400).json({ error: "Username must be at least 3 characters." });
        }
        if (!isValidEmail(email)) {
            return res.status(400).json({ error: "Please enter a valid email address." });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: "Password must be at least 6 characters." });
        }

        const [existing] = await db.query("SELECT id FROM users WHERE email = ?", [email]);
        if (existing.length > 0) {
            return res.status(409).json({ error: "That email already has an account. Try logging in instead." });
        }

        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

        const [result] = await db.query(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            [username, email, passwordHash]
        );

        const user = { id: result.insertId, username, email };
        setAuthCookie(res, signToken(user));
        return res.status(201).json({ user });
    } catch (err) {
        if (err && err.code === "ER_DUP_ENTRY") {
            return res.status(409).json({ error: "That email already has an account. Try logging in instead." });
        }
        console.error("[POST /api/register] error:", err);
        return res.status(500).json({ error: "Something went wrong while creating your account. Please try again." });
    }
});

// ── POST /api/login ───────────────────────────────────────────────────────
// Accepts either the username or the email in `identifier`, matching the
// existing login form which lets players sign in with either.
app.post("/api/login", async (req, res) => {
    try {
        const identifier = (req.body.identifier || req.body.email || req.body.username || "").trim();
        const password = req.body.password || "";

        if (!identifier || !password) {
            return res.status(400).json({ error: "Please enter your username/email and password." });
        }

        const [rows] = await db.query(
            "SELECT id, username, email, password_hash FROM users WHERE email = ? OR username = ? LIMIT 1",
            [identifier.toLowerCase(), identifier]
        );

        if (rows.length === 0) {
            return res.status(401).json({ error: "No account found with that username or email." });
        }

        const row = rows[0];
        const match = await bcrypt.compare(password, row.password_hash);
        if (!match) {
            return res.status(401).json({ error: "Incorrect password." });
        }

        const user = { id: row.id, username: row.username, email: row.email };
        setAuthCookie(res, signToken(user));
        return res.status(200).json({ user });
    } catch (err) {
        console.error("[POST /api/login] error:", err);
        return res.status(500).json({ error: "Something went wrong while logging in. Please try again." });
    }
});

// ── POST /api/logout ──────────────────────────────────────────────────────
app.post("/api/logout", (req, res) => {
    res.clearCookie("bow_token");
    return res.status(200).json({ ok: true });
});

// ── GET /api/users/me ─────────────────────────────────────────────────────
app.get("/api/users/me", requireAuth, async (req, res) => {
    try {
        const [rows] = await db.query(
            "SELECT id, username, email FROM users WHERE id = ? LIMIT 1",
            [req.user.id]
        );
        if (rows.length === 0) return res.status(404).json({ error: "User not found." });
        return res.status(200).json({ user: rows[0] });
    } catch (err) {
        console.error("[GET /api/users/me] error:", err);
        return res.status(500).json({ error: "Something went wrong. Please try again." });
    }
});

app.get("/api/health", (req, res) => res.json({ ok: true }));

// ── serve the game itself ─────────────────────────────────────────────────
// Books_of_Worlds.html must sit in this same folder (next to server.js).
// If it's inside a subfolder instead, change GAME_FILE below to match,
// e.g. "public/Books_of_Worlds.html".
const GAME_FILE = "Books_of_Worlds.html";
app.use(express.static(__dirname));
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, GAME_FILE));
});

app.listen(PORT, () => {
    console.log(`API running on http://localhost:${PORT}`);
});
