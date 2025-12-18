// tracking_routes.js
const express = require('express');
const router = express.Router();
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// ✅ Import unified authentication middleware
const { requireAuth } = require('./auth_middleware');

// ✅ Use /data/customers.db
const DATA_DIR = path.join(__dirname, 'data');
const customersDBPath = path.join(DATA_DIR, 'customers.db');
const db = new sqlite3.Database(customersDBPath, (err) => {
  if (err) {
    console.error('❌ Error opening DB for tracking:', err);
  } else {
    console.log('✅ Tracking DB connected:', customersDBPath);
  }
});


// ✅ Public: Get all tracking events for a given item QR (portal)
router.get('/tracking/:itemQR', (req, res) => {
  const { itemQR } = req.params;
  db.all(
    `SELECT * FROM tracking WHERE ItemQR = ? ORDER BY Timestamp DESC`,
    [itemQR],
    (err, rows) => {
      if (err) {
        console.error('Error fetching tracking:', err);
        return res.status(500).json({ error: 'Failed to retrieve tracking' });
      }
      res.json(rows);
    }
  );
});

// ✅ Staff/Admin: Add new tracking event (protected)
router.post('/tracking', requireAuth, (req, res) => {
  const d = req.body;
  const timestamp = new Date().toISOString();

  db.run(
    `
    INSERT INTO tracking (ItemID, ItemQR, Stage, Timestamp, Location, Notes, Image)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `,
    [d.ItemID, d.ItemQR, d.Stage, timestamp, d.Location, d.Notes, d.Image || ''],
    function (err) {
      if (err) {
        console.error('Error adding tracking:', err);
        return res.status(500).send('Failed to add tracking event');
      }
      res.send('Tracking event added');
    }
  );
});

module.exports = router;
