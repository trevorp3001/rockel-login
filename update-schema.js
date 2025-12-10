const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('customers.db');

db.serialize(() => {
  db.run(`ALTER TABLE customers ADD COLUMN Type TEXT`, (err) => {
    if (err && err.message.includes('duplicate column name')) {
      console.log('Column "Type" already exists. Skipping.');
    } else if (err) {
      console.error('Error adding Type column:', err.message);
    } else {
      console.log('✅ Column "Type" added successfully.');
    }
  });
});

db.close();
