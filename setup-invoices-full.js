const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('customers.db');

// Helper to get year suffix
const yearSuffix = new Date().getFullYear().toString().slice(-2);

// Run setup
db.serialize(() => {
  // Invoices table
  db.run(`
    CREATE TABLE IF NOT EXISTS invoices (
      InvoiceID INTEGER PRIMARY KEY AUTOINCREMENT,
      InvoiceNumber TEXT,
      CustomerID INTEGER,
      InvoiceDate TEXT,
      ReceiverName TEXT,
      Email TEXT,
      Phone1 TEXT,
      Phone2 TEXT,
      Phone3 TEXT,
      Address1 TEXT,
      Address2 TEXT,
      PostCode TEXT,
      Country TEXT,
      Notes TEXT,
      InvoiceQR TEXT
    )
  `);

  // Invoice items
  db.run(`
    CREATE TABLE IF NOT EXISTS invoice_items (
      ItemID INTEGER PRIMARY KEY AUTOINCREMENT,
      InvoiceID INTEGER,
      ItemName TEXT,
      Description TEXT,
      Quantity INTEGER,
      UnitCost REAL,
      TotalCost REAL,
      ContainerID INTEGER,
      ItemQR TEXT
    )
  `);

  // Payment records
  db.run(`
    CREATE TABLE IF NOT EXISTS payments (
      PaymentID INTEGER PRIMARY KEY AUTOINCREMENT,
      InvoiceID INTEGER,
      AmountPaid REAL,
      PaymentDate TEXT,
      PaymentMethod TEXT
    )
  `);

  // Preset items
  db.run(`
    CREATE TABLE IF NOT EXISTS preset_items (
      PresetID INTEGER PRIMARY KEY AUTOINCREMENT,
      ItemName TEXT,
      DefaultDescription TEXT,
      DefaultPrice REAL
    )
  `);

  // Containers
  db.run(`
    CREATE TABLE IF NOT EXISTS containers (
      ContainerID INTEGER PRIMARY KEY AUTOINCREMENT,
      ContainerNumber TEXT,
      ShipDate TEXT,
      ArrivalDate TEXT,
      Notes TEXT
    )
  `);

  console.log("✅ All invoice-related tables created successfully.");
});

db.close();
