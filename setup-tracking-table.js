const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('customers.db');

const trackingTable = `
CREATE TABLE IF NOT EXISTS tracking (
  TrackingID INTEGER PRIMARY KEY AUTOINCREMENT,
  ItemID INTEGER,
  ItemQR TEXT,
  Stage TEXT,
  Timestamp TEXT,
  Location TEXT,
  Notes TEXT,
  Image TEXT
);
`;

db.run(trackingTable, err => {
  if (err) {
    console.error("Error creating tracking table:", err);
  } else {
    console.log("✅ Tracking table created successfully!");
  }
  db.close();
});
