// feedback_routes.js
const express = require('express');
const router = express.Router();
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const multer = require('multer');
const fs = require('fs');

// ✅ Import unified authentication middleware
const { requireAuth } = require('./auth_middleware');

const customerDB = new sqlite3.Database('customers.db');

// File upload setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads'),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`;
    cb(null, uniqueName);
  }
});
const upload = multer({ storage });

// Serve feedback.html
router.get('/feedback', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'feedback.html'));
});

// List open feedback
router.get('/feedback/all', requireAuth, (req, res) => {
  customerDB.all(`
    SELECT f.*, c.[First Name] || ' ' || c.[Last Name] AS CustomerName
    FROM feedback f
    LEFT JOIN customers c ON f.CustomerID = c.CustomerID
    WHERE f.Status = 'Open'
    ORDER BY f.CreatedAt DESC
  `, [], (err, rows) => {
    if (err) {
      console.error('Failed to fetch feedback:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

// Submit new feedback
router.post('/feedback', express.json(), (req, res) => {
  const d = req.body;

  if (!d.CustomerID || !d.QueryType || !d.Message) {
    return res.status(400).send('Missing required fields');
  }

  const sql = `
    INSERT INTO feedback 
    (CustomerID, InvoiceID, BookingID, Title, Message, QueryType, Status, CreatedAt, UpdatedAt)
    VALUES (?, ?, ?, ?, ?, ?, 'Open', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
  `;

  const values = [
    d.CustomerID,
    d.InvoiceID || null,
    d.BookingID || null,
    d.Title || '',
    d.Message,
    d.QueryType
  ];

  customerDB.run(sql, values, function (err) {
    if (err) {
      console.error('❌ Failed to insert feedback:', err.message);
      return res.status(500).send('Failed to submit feedback');
    }
    res.send({ message: 'Feedback submitted', FeedbackID: this.lastID });
  });
});

// Update feedback
router.put('/feedback/:id', requireAuth, express.json(), (req, res) => {
  const { id } = req.params;
  const d = req.body;

  if (!d.Message || !d.QueryType || !d.Status) {
    return res.status(400).send('Missing required fields');
  }

  const sql = `
    UPDATE feedback
    SET 
      Title = ?, 
      Message = ?, 
      QueryType = ?, 
      Status = ?, 
      InvoiceID = ?, 
      BookingID = ?, 
      UpdatedAt = CURRENT_TIMESTAMP
    WHERE FeedbackID = ?
  `;

  const values = [
    d.Title || '',
    d.Message,
    d.QueryType,
    d.Status || 'Open',
    d.InvoiceID || null,
    d.BookingID || null,
    id
  ];

  customerDB.run(sql, values, function (err) {
    if (err) {
      console.error('❌ Failed to update feedback:', err.message);
      return res.status(500).send('Failed to update feedback');
    }
    res.send({ message: 'Feedback updated' });
  });
});

// Close feedback
router.post('/feedback/close/:id', requireAuth, (req, res) => {
  const id = req.params.id;
  customerDB.run(`
    UPDATE feedback SET Status = 'Closed', UpdatedAt = CURRENT_TIMESTAMP WHERE FeedbackID = ?
  `, [id], function (err) {
    if (err) {
      console.error('Failed to close feedback:', err);
      return res.status(500).send('Error closing feedback');
    }
    res.send('Feedback closed');
  });
});

// Filtered list for feedback-list.html
router.get('/api/feedback/filter', requireAuth, (req, res) => {
  const { type = '', status = '', invoiceId = '', start = '', end = '' } = req.query;

  let sql = `
    SELECT 
      f.*,
      c.[First Name] AS FirstName,
      c.[Last Name]  AS LastName
    FROM feedback f
    LEFT JOIN customers c ON c.CustomerID = f.CustomerID
    WHERE 1 = 1
  `;
  const params = [];

  if (type)      { sql += ` AND f.QueryType = ?`; params.push(type); }
  if (status)    { sql += ` AND f.Status = ?`; params.push(status); }
  if (invoiceId) { sql += ` AND f.InvoiceID = ?`; params.push(invoiceId); }
  if (start)     { sql += ` AND date(f.CreatedAt) >= date(?)`; params.push(start); }
  if (end)       { sql += ` AND date(f.CreatedAt) <= date(?)`; params.push(end); }

  sql += ` ORDER BY f.CreatedAt DESC`;

  customerDB.all(sql, params, (err, rows) => {
    if (err) {
      console.error('❌ Failed to filter feedback:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});


// Load all feedback for a customer
router.get('/feedback/:customerId', requireAuth, (req, res) => {
  const { customerId } = req.params;

  customerDB.all(`
    SELECT * FROM feedback 
    WHERE CustomerID = ? 
    ORDER BY CreatedAt DESC
  `, [customerId], (err, rows) => {
    if (err) {
      console.error('❌ Failed to fetch customer feedback:', err.message);
      return res.status(500).send('Failed to load feedback');
    }
    res.json(rows);
  });
});

// Delete feedback
router.delete('/feedback/:id', requireAuth, (req, res) => {
  const id = req.params.id;
  customerDB.run(`DELETE FROM feedback WHERE FeedbackID = ?`, [id], function (err) {
    if (err) {
      console.error('Failed to delete feedback:', err);
      return res.status(500).send('Error deleting feedback');
    }
    res.send('Feedback deleted');
  });
});

// Fetch invoices for dropdown
router.get('/feedback/invoices/:customerId', requireAuth, (req, res) => {
  const { customerId } = req.params;
  customerDB.all(`
    SELECT InvoiceID, InvoiceNumber, InvoiceDate 
    FROM invoices 
    WHERE CustomerID = ? 
    ORDER BY InvoiceDate DESC
  `, [customerId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to load invoices' });
    res.json(rows);
  });
});

// Fetch bookings for dropdown
router.get('/feedback/bookings/:customerId', requireAuth, (req, res) => {
  const { customerId } = req.params;
  customerDB.all(`
    SELECT BookingID, [Booking Date] 
    FROM bookings 
    WHERE CustomerID = ? 
    ORDER BY [Booking Date] DESC
  `, [customerId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to load bookings' });
    res.json(rows);
  });
});

// Add a reply (with optional attachment)
router.post('/feedback/:id/reply', requireAuth, upload.single('Attachment'), (req, res) => {
  const feedbackId = req.params.id;
  const { ReplyMessage } = req.body;
  const attachment = req.file ? req.file.filename : null;

  if (!ReplyMessage) {
    return res.status(400).send('Reply message is required');
  }

  const sql = `
    INSERT INTO feedback_replies 
    (FeedbackID, ReplyMessage, AttachmentPath, RepliedAt)
    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
  `;

  customerDB.run(sql, [feedbackId, ReplyMessage, attachment], function (err) {
    if (err) {
      console.error('❌ Failed to insert reply:', err.message);
      return res.status(500).send('Failed to add reply');
    }
    res.send({ message: 'Reply added', ReplyID: this.lastID });
  });
});

// Get all replies for a feedback
router.get('/feedback/replies/:id', requireAuth, (req, res) => {
  const feedbackId = req.params.id;

  customerDB.all(`
    SELECT * FROM feedback_replies 
    WHERE FeedbackID = ? 
    ORDER BY RepliedAt ASC
  `, [feedbackId], (err, rows) => {
    if (err) {
      console.error('❌ Failed to fetch replies:', err.message);
      return res.status(500).send('Failed to load replies');
    }
    res.json(rows);
  });
});

module.exports = router;
