const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');   // ✅ switched to bcryptjs
const db = new sqlite3.Database('users.db'); // adjust if your DB is customers.db


async function seed() {
  const username = "admin";
  const plainPassword = "ChangeMe123"; // 👈 choose a strong one
  const role = "Admin";

  const hash = await bcrypt.hash(plainPassword, 10);

  db.run(
    `INSERT INTO staff_users (Username, PasswordHash, Role) VALUES (?, ?, ?)`,
    [username, hash, role],
    function (err) {
      if (err) {
        console.error("❌ Failed to insert admin:", err.message);
      } else {
        console.log(`✅ Admin created with username '${username}'`);
      }
      db.close();
    }
  );
}

seed();
