const express = require('express');
const router = express.Router();
const path = require('path');                         // ⬅ add this
const sqlite3 = require('sqlite3').verbose();

// ✅ Import unified authentication middleware
const { requireAuth } = require('./auth_middleware');

// ✅ Use the SAME /data/customers.db as server.js
const DATA_DIR = path.join(__dirname, 'data');
const customersDBPath = path.join(DATA_DIR, 'customers.db');
const db = new sqlite3.Database(customersDBPath);

db.serialize(() => {
  db.run(
    `
    CREATE TABLE IF NOT EXISTS preset_items (
      PresetID INTEGER PRIMARY KEY AUTOINCREMENT,
      ItemName TEXT NOT NULL,
      DefaultDescription TEXT,
      DefaultPrice REAL NOT NULL
    )
    `,
    (err) => {
      if (err) {
        console.error('❌ Error ensuring preset_items table:', err.message);
      } else {
        console.log('✅ preset_items table is present.');
      }
    }
  );
});


console.log('📂 preset_items_routes using DB:', customersDBPath);


// Get all preset items (staff only)
router.get('/presets', requireAuth, (req, res) => {
  db.all('SELECT * FROM preset_items ORDER BY ItemName ASC', [], (err, rows) => {
    if (err) {
      console.error('❌ Failed to fetch presets:', err.message);
      return res.status(500).send('Error loading presets');
    }
    res.json(rows);
  });
});

// Add new preset item (staff only)
router.post('/presets', requireAuth, express.json(), (req, res) => {
  const { ItemName, DefaultDescription, DefaultPrice } = req.body;
  if (!ItemName) return res.status(400).send('ItemName is required');

  db.run(
    `INSERT INTO preset_items (ItemName, DefaultDescription, DefaultPrice)
     VALUES (?, ?, ?)`,
    [ItemName, DefaultDescription || '', DefaultPrice || 0],
    function (err) {
      if (err) {
        console.error('❌ Failed to insert preset:', err.message);
        return res.status(500).send('Error adding preset');
      }
      res.send({ message: 'Preset added', PresetID: this.lastID });
    }
  );
});

// Update preset item (staff only)
router.put('/presets/:id', requireAuth, express.json(), (req, res) => {
  const { id } = req.params;
  const { ItemName, DefaultDescription, DefaultPrice } = req.body;

  db.run(
    `UPDATE preset_items 
        SET ItemName = ?, DefaultDescription = ?, DefaultPrice = ?
      WHERE PresetID = ?`,
    [ItemName, DefaultDescription || '', DefaultPrice || 0, id],
    function (err) {
      if (err) {
        console.error('❌ Failed to update preset:', err.message);
        return res.status(500).send('Error updating preset');
      }
      res.send({ message: 'Preset updated' });
    }
  );
});

// Delete preset item (staff only)
router.delete('/presets/:id', requireAuth, (req, res) => {
  const { id } = req.params;

  db.run('DELETE FROM preset_items WHERE PresetID = ?', [id], function (err) {
    if (err) {
      console.error('❌ Failed to delete preset:', err.message);
      return res.status(500).send('Error deleting preset');
    }
    res.send({ message: 'Preset deleted' });
  });
});

module.exports = router;
