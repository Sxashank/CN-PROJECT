const express = require('express');
const cors = require('cors');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

const dbPath = path.resolve(__dirname, 'ids_logs.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('[!] Error connecting to SQLite database:', err.message);
  } else {
    console.log('[+] Connected to SQLite database.');

    db.run(`CREATE TABLE IF NOT EXISTS traffic_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      source_ip TEXT,
      dest_ip TEXT,
      protocol TEXT,
      dest_port INTEGER,
      classification TEXT,
      confidence REAL,
      is_blocked BOOLEAN
    )`);
  }
});

app.get('/api/logs', (req, res) => {
  const query = "SELECT * FROM traffic_logs ORDER BY id DESC LIMIT 1000";
  db.all(query, [], (err, rows) => {
    if (err) res.status(500).json({ error: 'Internal server error' });
    else res.json(rows);
  });
});

app.get('/api/attacks', (req, res) => {
  const query = "SELECT * FROM traffic_logs WHERE classification != 'Normal' ORDER BY id DESC LIMIT 1000";
  db.all(query, [], (err, rows) => {
    if (err) res.status(500).json({ error: 'Internal server error' });
    else res.json(rows);
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Node.js Backend is running on port ${PORT}`);
});
