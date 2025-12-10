const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('customers.db');

// Drop the old containers table if it exists
db.serialize(() => {
  console.log('Dropping old containers table...');
  db.run('DROP TABLE IF EXISTS containers', (err) => {
    if (err) {
      console.error('Error dropping table:', err.message);
    } else {
      console.log('Old containers table dropped.');
    }

    // Now recreate the table with correct schema
    const containerSchema = `
      CREATE TABLE IF NOT EXISTS containers (
        ContainerID INTEGER PRIMARY KEY AUTOINCREMENT,
        Vessel TEXT,
        Carrier TEXT,
        Status TEXT,
        DateLoaded TEXT,
        ETD TEXT,
        ETA TEXT,
        DateArrive TEXT,
        DateClear TEXT,
        BookingRef TEXT,
        ContainerNumber TEXT,
        ContainerSeal TEXT,
        Paid TEXT,
        Cost REAL,
        Notes TEXT,
        Weight TEXT,
        Size TEXT
      )
    `;
    db.run(containerSchema, (err) => {
      if (err) {
        console.error('Error creating table:', err.message);
      } else {
        console.log('✅ Containers table recreated successfully.');
      }
    });
  });
});
