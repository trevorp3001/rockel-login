const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('customers.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS customers (
    CustomerID INTEGER PRIMARY KEY AUTOINCREMENT,
    Company TEXT,
    [First Name] TEXT,
    [Last Name] TEXT,
    [E-mail Address] TEXT,
    [Phone 1] TEXT,
    [Phone 2] TEXT,
    [Phone 3] TEXT,
    [Fax Number] TEXT,
    [Address 1] TEXT,
    [Address 2] TEXT,
    [Address 3] TEXT,
    [Post Code] TEXT,
    Country TEXT,
    [Web Page] TEXT,
    Notes TEXT,
    Category TEXT
  )`);

  // Insert sample data
  const stmt = db.prepare(`INSERT INTO customers 
    (Company, [First Name], [Last Name], [E-mail Address], [Phone 1], [Address 1], [Post Code], Country, Category) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);

  stmt.run("Doe Co.", "John", "Doe", "john@doe.com", "555-1234", "123 King St", "SL123", "Sierra Leone", "Shipping");
  stmt.run("Acme Ltd.", "Jane", "Smith", "jane@acme.com", "555-5678", "456 Queen Ave", "SL456", "Sierra Leone", "Retail");

  stmt.finalize();
});

db.close();
