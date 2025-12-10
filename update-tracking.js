const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('customers.db');

db.run("ALTER TABLE tracking ADD COLUMN ContainerID INTEGER", (err) => {
  if (err) {
    console.error("❌ Already added or error:", err.message);
  } else {
    console.log("✅ ContainerID column added to tracking table.");
  }
  db.close();
});
