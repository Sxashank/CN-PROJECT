const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const server = http.createServer(app);

app.use(cors({ origin: '*' }));

const dbPath = path.resolve(__dirname, 'ids_logs.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (!err) {
    db.run(`CREATE TABLE IF NOT EXISTS traffic_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      source_ip TEXT, dest_ip TEXT, protocol TEXT,
      dest_port INTEGER, classification TEXT,
      confidence REAL, is_blocked BOOLEAN
    )`);
  }
});

app.get('/api/logs', (req, res) => {
  db.all("SELECT * FROM traffic_logs ORDER BY id DESC LIMIT 1000", [], (err, rows) => {
    res.json(err ? [] : rows);
  });
});

const io = new Server(server, { cors: { origin: '*', methods: ['GET', 'POST'] } });

io.on('connection', (socket) => {
  console.log(`[+] New client connected: ${socket.id}`);

  socket.on('live_traffic', (packetData) => {
    const mappedData = {
      timestamp: packetData.timestamp,
      source_ip: packetData.source_ip,
      dest_ip: packetData.destination_ip,
      protocol: packetData.protocol,
      dest_port: packetData.destination_port,
      classification: packetData.ml_classification,
      confidence: packetData.ml_confidence,
      is_blocked: false, // Blocking not implemented yet!
      source_name: packetData.source_name,
      destination_name: packetData.destination_name,
      packet_size: packetData.packet_size,
      speed_kbps: packetData.speed_kbps
    };

    io.emit('live_traffic', mappedData);

    const ts = new Date(mappedData.timestamp * 1000).toISOString();
    db.run(`INSERT INTO traffic_logs (timestamp, source_ip, dest_ip, protocol, dest_port, classification, confidence, is_blocked) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
           [ts, mappedData.source_ip, mappedData.dest_ip, mappedData.protocol, mappedData.dest_port, mappedData.classification, mappedData.confidence, false]);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Node.js Backend Bridge running on port ${PORT}`);
});
