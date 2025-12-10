const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('users.db');

// Create users table
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);

  // Add a test user (username: admin, password: password123)
  db.run(`INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)`, [
    'admin',
    'password123'
  ]);
});

db.close();
