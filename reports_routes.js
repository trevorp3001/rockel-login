const express = require('express');
const router = express.Router();

const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// ✅ Import unified authentication middleware
const { requireAuth } = require('./auth_middleware');

// ✅ Use /data/customers.db
const DATA_DIR = path.join(__dirname, 'data');
const customersDBPath = path.join(DATA_DIR, 'customers.db');
const customerDB = new sqlite3.Database(customersDBPath, (err) => {
  if (err) console.error('❌ Error opening DB for reports:', err);
  else console.log('✅ Reports DB connected:', customersDBPath);
});


/* -------------------------
   FINANCE REPORTS
------------------------- */

// Revenue by month (Invoices vs Payments)
router.get('/revenue-by-month', requireAuth, (req, res) => {
  const sql = `
    SELECT strftime('%Y-%m', i.InvoiceDate) AS Month,
           SUM(ii.TotalCost) AS InvoiceTotal,
           SUM(p.AmountPaid) AS PaymentTotal,
           COUNT(DISTINCT i.InvoiceID) AS InvoiceCount,
           COUNT(DISTINCT b.BookingID) AS BookingCount
    FROM invoices i
    LEFT JOIN invoice_items ii ON i.InvoiceID = ii.InvoiceID
    LEFT JOIN payments p ON i.InvoiceID = p.InvoiceID
    LEFT JOIN bookings b ON i.InvoiceID = b.InvoiceID
    GROUP BY Month
    ORDER BY Month;
  `;
  customerDB.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});


/* -------------------------
   CUSTOMER REPORTS
------------------------- */

// Top customers by spend
router.get('/top-customers', requireAuth, (req, res) => {
  const sql = `
    SELECT c.CustomerID,
           c.[First Name] AS FirstName,
           c.[Last Name] AS LastName,
           c.Company,
           SUM(ii.TotalCost) AS TotalSpend
    FROM customers c
    JOIN invoices i ON c.CustomerID = i.CustomerID
    JOIN invoice_items ii ON i.InvoiceID = ii.InvoiceID
    GROUP BY c.CustomerID
    ORDER BY TotalSpend DESC
    LIMIT 20;
  `;
  customerDB.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Referral summary
router.get('/referral-summary', requireAuth, (req, res) => {
  const sql = `
    SELECT ReferrerID,
           COUNT(*) AS ReferralsMade,
           SUM(CASE WHEN RewardIssued = 1 THEN 20 ELSE 0 END) +
           SUM(CASE WHEN BonusIssued = 1 THEN 50 ELSE 0 END) AS TotalRewards
    FROM referrals
    GROUP BY ReferrerID
    ORDER BY ReferralsMade DESC;
  `;
  customerDB.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

// Inactive customers (>6 months no booking)
router.get('/inactive-customers', requireAuth, (req, res) => {
  const sql = `
    SELECT c.CustomerID,
           c.[First Name] AS FirstName,
           c.[Last Name] AS LastName,
           c.Company,
           MAX(b.[Booking Date]) AS LastBooking
    FROM customers c
    LEFT JOIN bookings b ON c.CustomerID = b.CustomerID
    GROUP BY c.CustomerID
    HAVING LastBooking IS NULL
       OR julianday('now') - julianday(LastBooking) > 180
    ORDER BY LastBooking;
  `;
  customerDB.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

/* -------------------------
   STAFF REPORTS
------------------------- */

// Staff job logs
router.get('/staff-logs', requireAuth, (req, res) => {
  const sql = `
    SELECT s.StaffID, s.Name, s.Role,
           j.BookingID, j.AllocatedAt
    FROM staff s
    JOIN job_allocations j ON s.StaffID = j.StaffID
    ORDER BY j.AllocatedAt DESC
    LIMIT 100;
  `;
  customerDB.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Allocated vs completed jobs
router.get('/staff-allocation-summary', requireAuth, (req, res) => {
  const sql = `
    SELECT s.StaffID, s.Name,
           COUNT(j.BookingID) AS AllocatedJobs,
           SUM(CASE WHEN b.Status = 'Completed' THEN 1 ELSE 0 END) AS CompletedJobs
    FROM staff s
    LEFT JOIN job_allocations j ON s.StaffID = j.StaffID
    LEFT JOIN bookings b ON j.BookingID = b.BookingID
    GROUP BY s.StaffID;
  `;
  customerDB.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Staff performance (jobs/day)
router.get('/staff-performance', requireAuth, (req, res) => {
  const sql = `
    SELECT s.StaffID, s.Name,
           CASE WHEN COUNT(DISTINCT date(j.AllocatedAt)) > 0
                THEN COUNT(j.BookingID) * 1.0 / COUNT(DISTINCT date(j.AllocatedAt))
                ELSE 0 END AS JobsPerDay
    FROM staff s
    LEFT JOIN job_allocations j ON s.StaffID = j.StaffID
    GROUP BY s.StaffID;
  `;
  customerDB.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

/* -------------------------
   FEEDBACK REPORTS
------------------------- */

router.get('/feedback-summary', requireAuth, (req, res) => {
  const sql = `
    SELECT QueryType, Status, COUNT(*) AS Count
    FROM feedback
    GROUP BY QueryType, Status;
  `;
  customerDB.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

/* -------------------------
   TRACKING REPORTS
------------------------- */

// Tracking logs with date filters
router.get('/tracking', requireAuth, (req, res) => {
  const { start, end } = req.query;
  let sql = `
    SELECT t.ItemID, t.Stage, t.Timestamp, t.Notes,
           i.ItemQR, c.ContainerNumber
    FROM tracking t
    LEFT JOIN invoice_items i ON t.ItemID = i.ItemID
    LEFT JOIN containers c ON i.ContainerID = c.ContainerID
    WHERE 1=1
  `;
  const params = [];
  if (start) {
    sql += ` AND t.Timestamp >= ?`;
    params.push(start);
  }
  if (end) {
    sql += ` AND t.Timestamp <= ?`;
    params.push(end);
  }
  sql += ` ORDER BY t.Timestamp DESC LIMIT 500`;

  customerDB.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// CSV export with optional date filters
router.get('/tracking/export', requireAuth, (req, res) => {
  const { start, end } = req.query;

  let sql = `
    SELECT t.ItemID, i.ItemQR, t.Stage, t.Timestamp, t.Notes, c.ContainerNumber
    FROM tracking t
    LEFT JOIN invoice_items i ON t.ItemID = i.ItemID
    LEFT JOIN containers c ON i.ContainerID = c.ContainerID
    WHERE 1=1
  `;
  const params = [];

  if (start) {
    sql += ` AND t.Timestamp >= ?`;
    params.push(start);
  }
  if (end) {
    sql += ` AND t.Timestamp <= ?`;
    params.push(end);
  }

  sql += ` ORDER BY t.Timestamp DESC LIMIT 1000`;

  customerDB.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });

    let csv = "ItemID,ItemQR,Stage,Timestamp,Notes,ContainerNumber\n";
    rows.forEach(r => {
      csv += `${r.ItemID},${r.ItemQR || ''},${r.Stage},${r.Timestamp},${r.Notes || ''},${r.ContainerNumber || ''}\n`;
    });

    res.header("Content-Type", "text/csv");
    res.attachment("tracking_report.csv");
    res.send(csv);
  });
});

// Aged receivables
router.get('/aged-receivables', requireAuth, (req, res) => {
  const sql = `
    SELECT i.InvoiceID,
           i.InvoiceNumber,
           i.InvoiceDate,
           c.[First Name] || ' ' || c.[Last Name] AS CustomerName,
           SUM(ii.TotalCost) - IFNULL(SUM(p.AmountPaid), 0) AS Balance,
           julianday('now') - julianday(i.InvoiceDate) AS DaysOutstanding
    FROM invoices i
    JOIN customers c ON i.CustomerID = c.CustomerID
    LEFT JOIN invoice_items ii ON i.InvoiceID = ii.InvoiceID
    LEFT JOIN payments p ON i.InvoiceID = p.InvoiceID
    GROUP BY i.InvoiceID
    HAVING Balance > 0
    ORDER BY DaysOutstanding DESC;
  `;
  customerDB.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });

    // Categorise into aging buckets
    const results = rows.map(r => ({
      ...r,
      AgeBand: r.DaysOutstanding <= 30 ? '0-30' :
               r.DaysOutstanding <= 60 ? '31-60' :
               r.DaysOutstanding <= 90 ? '61-90' : '90+'
    }));
    res.json(results);
  });
});

// Inactive customers (>3 months) — staff only
router.get('/inactive-customers', requireAuth, (req, res) => {
  const sql = `
    SELECT c.CustomerID,
           c.[First Name] AS FirstName,
           c.[Last Name] AS LastName,
           c.Company,
           MAX(b.[Booking Date]) AS LastBooking
    FROM customers c
    LEFT JOIN bookings b ON c.CustomerID = b.CustomerID
    GROUP BY c.CustomerID
    HAVING LastBooking IS NULL
       OR julianday('now') - julianday(LastBooking) > 90
    ORDER BY LastBooking;
  `;
  customerDB.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Staff job logs (driver/helper/van)
router.get('/job-logs', requireAuth, (req, res) => {
  const sql = `
    SELECT j.BookingID,
           j.DriverName,
           j.Helper1Name,
           j.Helper2Name,
           j.Van,
           j.AllocatedAt,
           b.Status AS BookingStatus,
           c.[First Name] || ' ' || c.[Last Name] AS CustomerName
    FROM job_allocations j
    LEFT JOIN bookings b ON j.BookingID = b.BookingID
    LEFT JOIN customers c ON b.CustomerID = c.CustomerID
    ORDER BY j.AllocatedAt DESC
    LIMIT 100;
  `;
  customerDB.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// CSV export - Aged Receivables
router.get('/aged-receivables/export', requireAuth, (req, res) => {
  const sql = `
    SELECT i.InvoiceNumber, c.[First Name] || ' ' || c.[Last Name] AS CustomerName,
           i.InvoiceDate,
           SUM(ii.TotalCost) - IFNULL(SUM(p.AmountPaid), 0) AS Balance,
           julianday('now') - julianday(i.InvoiceDate) AS DaysOutstanding
    FROM invoices i
    JOIN customers c ON i.CustomerID = c.CustomerID
    LEFT JOIN invoice_items ii ON i.InvoiceID = ii.InvoiceID
    LEFT JOIN payments p ON i.InvoiceID = p.InvoiceID
    GROUP BY i.InvoiceID
    HAVING Balance > 0
    ORDER BY DaysOutstanding DESC;
  `;
  customerDB.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });

    let csv = "InvoiceNumber,CustomerName,InvoiceDate,Balance,DaysOutstanding\n";
    rows.forEach(r => {
      csv += `${r.InvoiceNumber},${r.CustomerName},${r.InvoiceDate},${r.Balance},${r.DaysOutstanding}\n`;
    });

    res.header("Content-Type", "text/csv");
    res.attachment("aged_receivables.csv");
    res.send(csv);
  });
});

// CSV export - Inactive Customers
router.get('/inactive-customers/export', requireAuth, (req, res) => {
  const sql = `
    SELECT c.CustomerID, c.[First Name] AS FirstName, c.[Last Name] AS LastName,
           c.Company, MAX(b.[Booking Date]) AS LastBooking
    FROM customers c
    LEFT JOIN bookings b ON c.CustomerID = b.CustomerID
    GROUP BY c.CustomerID
    HAVING LastBooking IS NULL OR julianday('now') - julianday(LastBooking) > 90
    ORDER BY LastBooking;
  `;
  customerDB.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });

    let csv = "CustomerID,FirstName,LastName,Company,LastBooking\n";
    rows.forEach(r => {
      csv += `${r.CustomerID},${r.FirstName},${r.LastName},${r.Company || ''},${r.LastBooking || 'Never'}\n`;
    });

    res.header("Content-Type", "text/csv");
    res.attachment("inactive_customers.csv");
    res.send(csv);
  });
});

// CSV export - Staff Job Logs
router.get('/job-logs/export', requireAuth, (req, res) => {
  const sql = `
    SELECT j.BookingID, c.[First Name] || ' ' || c.[Last Name] AS CustomerName,
           j.DriverName, j.Helper1Name, j.Helper2Name, j.Van,
           j.AllocatedAt, b.Status AS BookingStatus
    FROM job_allocations j
    LEFT JOIN bookings b ON j.BookingID = b.BookingID
    LEFT JOIN customers c ON b.CustomerID = c.CustomerID
    ORDER BY j.AllocatedAt DESC
    LIMIT 1000;
  `;
  customerDB.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });

    let csv = "BookingID,CustomerName,DriverName,Helper1Name,Helper2Name,Van,AllocatedAt,BookingStatus\n";
    rows.forEach(r => {
      csv += `${r.BookingID},${r.CustomerName || ''},${r.DriverName || ''},${r.Helper1Name || ''},${r.Helper2Name || ''},${r.Van || ''},${r.AllocatedAt},${r.BookingStatus || ''}\n`;
    });

    res.header("Content-Type", "text/csv");
    res.attachment("staff_job_logs.csv");
    res.send(csv);
  });
});


module.exports = router;
