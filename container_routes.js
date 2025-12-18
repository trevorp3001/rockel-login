// container_routes.js
const express = require('express');
const router = express.Router();

// ✅ Import unified authentication middleware
const { requireAuth } = require('./auth_middleware');

const path = require('path');
const sqlite3 = require('sqlite3').verbose();

// ✅ Use the same /data/customers.db as server.js
const DATA_DIR = path.join(__dirname, 'data');
const customersDBPath = path.join(DATA_DIR, 'customers.db');
const customerDB = new sqlite3.Database(customersDBPath);

console.log('📂 container_routes using DB:', customersDBPath);


/**
 * NOTE ABOUT PATHS
 * This router is intended to be mounted at /containers
 *   app.use('/containers', containerRoutes)
 *
 * So a route defined here as:
 *   router.get('/all', ...)
 * will be reachable at:
 *   GET /containers/all
 *
 * Avoid repeating '/containers' inside route definitions.
 */

/* -----------------------------
 * PAGE ROUTES (staff-only pages)
 * ----------------------------- */

// /containers/containers-list  -> serves public/containers-list.html
router.get('/containers-list', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'containers-list.html'));
});

// /containers/add-container -> serves public/add-container.html
router.get('/add-container', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'add-container.html'));
});

// /containers/edit-container -> serves public/edit-container.html
router.get('/edit-container', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'edit-container.html'));
});

/* -----------------------------
 * DATA ROUTES (CRUD, staff-only)
 * ----------------------------- */

// List all containers
// GET /containers/all
router.get('/all', requireAuth, (req, res) => {
  customerDB.all(
    `SELECT * FROM containers ORDER BY ContainerID DESC`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Failed to fetch containers' });
      res.json(rows);
    }
  );
});

// GET /containers/eligible
router.get('/eligible', requireAuth, (req, res) => {
  customerDB.all(
    `SELECT ContainerID, ContainerNumber, Vessel, Status
       FROM containers
      WHERE Status != 'Arrived'
      ORDER BY ContainerID DESC`,
    [],
    (err, rows) => {
      if (err) {
        console.error('Failed to fetch containers:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(rows);
    }
  );
});

// GET /containers/latest-delays
router.get('/latest-delays', requireAuth, (req, res) => {
  customerDB.all(
    `SELECT d.ContainerID, d.NewETA, d.Reason
       FROM container_delays d
       INNER JOIN (
         SELECT ContainerID, MAX(DelayDate) as MaxDate
           FROM container_delays
          GROUP BY ContainerID
       ) latest
       ON latest.ContainerID = d.ContainerID
      AND latest.MaxDate = d.DelayDate`,
    [],
    (err, rows) => {
      if (err) {
        console.error("Failed to fetch latest delays:", err.message);
        return res.status(500).send("Error fetching delay data");
      }
      const delays = {};
      rows.forEach(d => {
        delays[String(d.ContainerID)] = { NewETA: d.NewETA, Reason: d.Reason };
      });
      res.json(delays);
    }
  );
});

// Get one container
// GET /containers/:id
router.get('/:id', requireAuth, (req, res) => {
  customerDB.get(`SELECT * FROM containers WHERE ContainerID = ?`, [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch container' });
    if (!row) return res.status(404).json({ error: 'Not found' });
    res.json(row);
  });
});

// Create container
// POST /containers/
router.post('/', requireAuth, (req, res) => {
  const d = req.body;
  customerDB.run(
    `
    INSERT INTO containers 
      (ContainerNumber, Vessel, Carrier, BookingRef, DateLoaded, ETD, ETA, DateArrived, DateCleared, Size, Status, ContainerSeal, Notes, Paid, Cost, VoyageNumber, CustomerContainer, VehicleRoro)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    [
      d.ContainerNumber, d.Vessel, d.Carrier, d.BookingRef, d.DateLoaded, d.ETD, d.ETA,
      d.DateArrived, d.DateCleared, d.Size, d.Status, d.ContainerSeal, d.Notes, d.Paid, d.Cost,
      d.VoyageNumber || '',
      d.CustomerContainer ? 1 : 0,
      d.VehicleRoro ? 1 : 0
    ],
    function (err) {
      if (err) return res.status(500).send('Failed to add container');
      // Redirect back to the list page under this mount
      res.redirect('/containers/containers-list');
    }
  );
});

// Update container
// PUT /containers/:id  (you may still hit this with POST from your form; keeping PUT is more RESTful)
router.put('/:id', requireAuth, (req, res) => {
  const d = req.body;
  customerDB.run(
    `
    UPDATE containers SET
      ContainerNumber = ?, Vessel = ?, Carrier = ?, BookingRef = ?, DateLoaded = ?, ETD = ?, ETA = ?,
      DateArrived = ?, DateCleared = ?, Size = ?, Status = ?, ContainerSeal = ?, Notes = ?, Paid = ?, Cost = ?,
      VoyageNumber = ?, CustomerContainer = ?, VehicleRoro = ?
    WHERE ContainerID = ?
    `,
    [
      d.ContainerNumber, d.Vessel, d.Carrier, d.BookingRef, d.DateLoaded, d.ETD, d.ETA,
      d.DateArrived, d.DateCleared, d.Size, d.Status, d.ContainerSeal, d.Notes, d.Paid, d.Cost,
      d.VoyageNumber || '',
      d.CustomerContainer ? 1 : 0,
      d.VehicleRoro ? 1 : 0,
      req.params.id
    ],
    function (err) {
      if (err) return res.status(500).send('Failed to update container');
      res.send('Container updated');
    }
  );
});

// If your form still POSTs for update, keep this compatibility route:
router.post('/:id', requireAuth, (req, res) => {
  const d = req.body;
  customerDB.run(
    `
    UPDATE containers SET
      ContainerNumber = ?, Vessel = ?, Carrier = ?, BookingRef = ?, DateLoaded = ?, ETD = ?, ETA = ?,
      DateArrived = ?, DateCleared = ?, Size = ?, Status = ?, ContainerSeal = ?, Notes = ?, Paid = ?, Cost = ?,
      VoyageNumber = ?, CustomerContainer = ?, VehicleRoro = ?
    WHERE ContainerID = ?
    `,
    [
      d.ContainerNumber, d.Vessel, d.Carrier, d.BookingRef, d.DateLoaded, d.ETD, d.ETA,
      d.DateArrived, d.DateCleared, d.Size, d.Status, d.ContainerSeal, d.Notes, d.Paid, d.Cost,
      d.VoyageNumber || '',
      d.CustomerContainer ? 1 : 0,
      d.VehicleRoro ? 1 : 0,
      req.params.id
    ],
    function (err) {
      if (err) return res.status(500).send('Failed to update container');
      res.send('Container updated');
    }
  );
});

// Delete container
// DELETE /containers/:id
router.delete('/:id', requireAuth, (req, res) => {
  customerDB.run(`DELETE FROM containers WHERE ContainerID = ?`, [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'Failed to delete container' });
    res.json({ success: true });
  });
});

/* -----------------------------
 * DELAYS (staff-only)
 * ----------------------------- */

// Add a delay
// POST /containers/:id/delays
router.post('/:id/delays', requireAuth, (req, res) => {
  const { id } = req.params;
  const { DelayDate, NewETA, Reason } = req.body;

  customerDB.run(
    `INSERT INTO container_delays (ContainerID, DelayDate, NewETA, Reason)
     VALUES (?, ?, ?, ?)`,
    [id, DelayDate, NewETA, Reason],
    function (err) {
      if (err) {
        console.error('❌ Failed to add delay:', err.message);
        return res.status(500).send('Failed to record delay');
      }
      res.send('Delay added');
    }
  );
});

// Get delays for a container
// GET /containers/:id/delays
router.get('/:id/delays', requireAuth, (req, res) => {
  const { id } = req.params;

  customerDB.all(
    `SELECT DelayDate, NewETA, Reason
       FROM container_delays
      WHERE ContainerID = ?
      ORDER BY DelayDate DESC`,
    [id],
    (err, rows) => {
      if (err) {
        console.error('❌ Failed to fetch delays:', err.message);
        return res.status(500).send('Failed to fetch delays');
      }
      res.json(rows);
    }
  );
});

// Delete a single delay by date
// DELETE /containers/:id/delays/:date
router.delete('/:id/delays/:date', requireAuth, (req, res) => {
  const { id, date } = req.params;
  customerDB.run(
    `DELETE FROM container_delays
      WHERE ContainerID = ? AND DelayDate = ?`,
    [id, date],
    function (err) {
      if (err) {
        console.error('❌ Failed to delete delay:', err.message);
        return res.status(500).send('Failed to delete delay');
      }
      res.send('Delay deleted');
    }
  );
});

module.exports = router;
