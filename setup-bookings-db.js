const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('customers.db');

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS bookings (
      BookingID INTEGER PRIMARY KEY AUTOINCREMENT,
      CustomerID INTEGER,
      [Afternoon/Evening] TEXT,
      [Booking Date] TEXT,
      Notes TEXT,
      Status TEXT,
      InvoiceID INTEGER
    )
  `, err => {
    if (err) {
      console.error("Failed to create bookings table:", err.message);
    } else {
      console.log("✅ Bookings table created successfully.");
    }
  });
});

db.close();
