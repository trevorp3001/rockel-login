/**
 * Rockel Shipping Customer Portal Routes
 *
 * TODO: Stripe/Payment Integration
 * - See route: POST /api/pay/:invoiceId
 * - Currently mocked. Replace with Stripe Checkout Session creation.
 * - Steps:
 *   1. npm install stripe
 *   2. Add `require('stripe')(process.env.STRIPE_SECRET_KEY)`
 *   3. Replace mock insert with Stripe session code
 *   4. Redirect customer to session.url
 */


// customer_portal_routes.js

const express = require('express');
const router = express.Router();

const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// ✅ Use the same /data/customers.db as server.js
const DATA_DIR = path.join(__dirname, 'data');
const customersDBPath = path.join(DATA_DIR, 'customers.db');
const customerDB = new sqlite3.Database(customersDBPath, (err) => {
  if (err) {
    console.error('❌ Error opening DB for customer portal:', err);
  } else {
    console.log('✅ Customer portal DB connected:', customersDBPath);
  }
});


// ✅ Import unified authentication middleware
const { requireAuth } = require('./auth_middleware');
const { requirePortal } = require('./auth_middleware');

// =========================
// Wave 3: Portal login protection
// =========================

// 15-minute rolling window for counting attempts
const PORTAL_LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

// After this many failures in the window → hard lock
const PORTAL_LOGIN_HARD_LOCK_THRESHOLD = 10;

// Hard lock duration: 3 hours
const PORTAL_LOGIN_HARD_LOCK_DURATION_MS = 3 * 60 * 60 * 1000; // 3 hours

// Track attempts per (postcode + invoiceNumber) combo
// key: normalized "POSTCODE|INVOICENUMBER"
const portalLoginAttempts = new Map();

function getPortalLoginState(key) {
  let state = portalLoginAttempts.get(key);
  const now = Date.now();

  if (!state) {
    state = {
      count: 0,
      firstAttemptAt: now,
      lockedUntil: 0
    };
    portalLoginAttempts.set(key, state);
  } else {
    // If the window expired and it's not currently locked, reset the counter
    if (now - state.firstAttemptAt > PORTAL_LOGIN_WINDOW_MS && now > state.lockedUntil) {
      state.count = 0;
      state.firstAttemptAt = now;
    }
  }

  return state;
}

function isPortalLoginLocked(key) {
  const state = getPortalLoginState(key);
  const now = Date.now();

  if (state.lockedUntil && now < state.lockedUntil) {
    return { locked: true, remainingMs: state.lockedUntil - now };
  }
  return { locked: false, remainingMs: 0 };
}

function registerPortalLoginFailure(key) {
  const state = getPortalLoginState(key);
  const now = Date.now();

  state.count += 1;

  // When threshold is reached, hard lock for 3 hours
  if (state.count >= PORTAL_LOGIN_HARD_LOCK_THRESHOLD) {
    state.lockedUntil = now + PORTAL_LOGIN_HARD_LOCK_DURATION_MS;
  }
}

function resetPortalLoginAttempts(key) {
  portalLoginAttempts.delete(key);
}

function minutesFromMs(ms) {
  return Math.ceil(ms / (60 * 1000));
}

// At the top of customer_portal_routes.js, after customerDB is available:

function getReferralCreditForCustomer(customerId) {
  const REWARD_VALUE = 20;  // £20 per normal referral
  const BONUS_VALUE  = 50;  // £50 per bonus at 5 referrals

  return new Promise((resolve, reject) => {
    // 1) Total earned from referrals table
    customerDB.get(`
      SELECT 
        COALESCE(SUM(CASE WHEN RewardIssued = 1 THEN 1 ELSE 0 END), 0) AS rewards,
        COALESCE(SUM(CASE WHEN BonusIssued  = 1 THEN 1 ELSE 0 END), 0) AS bonuses
      FROM referrals
      WHERE ReferrerID = ?
    `, [customerId], (err, earnRow) => {
      if (err) return reject(err);

      const rewards = earnRow?.rewards || 0;
      const bonuses = earnRow?.bonuses || 0;
      const totalEarned = (rewards * REWARD_VALUE) + (bonuses * BONUS_VALUE);

      // 2) Total already used on invoices as referral credit
      customerDB.get(`
        SELECT COALESCE(SUM(p.AmountPaid), 0) AS used
        FROM payments p
        JOIN invoices i ON p.InvoiceID = i.InvoiceID
        WHERE i.CustomerID = ? AND p.PaymentMethod = 'Referral Credit'
      `, [customerId], (err2, usedRow) => {
        if (err2) return reject(err2);

        const used = usedRow?.used || 0;
        const available = Math.max(totalEarned - used, 0);

        resolve({
          rewards,
          bonuses,
          totalEarned,
          used,
          available
        });
      });
    });
  });
}


// --- 1. Login Route ---
// ✅ Revised login route that requires BOTH postcode AND invoice number to match
router.post('/login', (req, res) => {
  console.log('Incoming body at login:', req.body);

  if (!req.body || Object.keys(req.body).length === 0) {
    return res.status(400).json({ error: 'Empty body received' });
  }

  const { postcode, invoiceNumber } = req.body;
  if (!postcode || !invoiceNumber) {
    return res.status(400).json({ error: 'Postcode and invoice number required' });
  }

  // 🔐 Build a normalized key for rate-limiting
  const normalizedPostcode = (postcode || '')
    .toUpperCase()
    .replace(/\s+/g, '');
  const normalizedInvoice = (invoiceNumber || '').toString().trim().toUpperCase();
  const loginKey = `${normalizedPostcode}|${normalizedInvoice}`;

  // 1️⃣ Check lock status before touching the DB
  const { locked, remainingMs } = isPortalLoginLocked(loginKey);
  if (locked) {
    const mins = minutesFromMs(remainingMs);
    return res.status(429).json({
      error: 'Too many attempts, contact administrator.',
      locked: true,
      retryAfterMinutes: mins
    });
  }

  const sql = `
    SELECT DISTINCT c.CustomerID
    FROM customers c
    JOIN invoices i ON i.CustomerID = c.CustomerID
    WHERE REPLACE(UPPER(c.[Post Code]), ' ', '') = REPLACE(UPPER(?), ' ', '')
      AND i.InvoiceNumber = ?
    LIMIT 1
  `;

  customerDB.get(sql, [postcode, invoiceNumber], (err, row) => {
    if (err) {
      console.error('Login lookup error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (!row) {
      // 🔴 No match → count as failed attempt
      registerPortalLoginFailure(loginKey);
      return res.status(404).json({ error: 'No matching customer found' });
    }

    // ✅ Success → reset attempts
    resetPortalLoginAttempts(loginKey);

    // 🔐 ADD THIS: regenerate session before setting portal flags
    req.session.regenerate((regenErr) => {
      if (regenErr) {
        console.error('Session regenerate error (portal login):', regenErr);
        return res.status(500).json({ error: 'Login error, please try again.' });
      }

      // ✅ Store session details for portal
      req.session.portalUser = row.CustomerID;
      req.session.customerId = row.CustomerID;
      req.session.portalAuthenticated = true;

      console.log(`✅ Customer portal login OK (CustomerID: ${row.CustomerID})`);
      res.json({ success: true, customerId: row.CustomerID });
    });
  });
});



// --- 2. Get Invoices by CustomerID ---
router.get('/:customerId/invoices', requirePortal, (req, res) => {
  if (parseInt(req.params.customerId, 10) !== parseInt(req.session.customerId, 10)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const { customerId } = req.params;
  const sql = `
    SELECT
      i.InvoiceID,
      i.InvoiceNumber,
      i.InvoiceDate,
      COALESCE((SELECT SUM(ii.TotalCost) FROM invoice_items ii WHERE ii.InvoiceID = i.InvoiceID), 0) AS Total,
      COALESCE((SELECT SUM(p.AmountPaid) FROM payments p WHERE p.InvoiceID = i.InvoiceID), 0) AS Paid
    FROM invoices i
    WHERE i.CustomerID = ?
    ORDER BY i.InvoiceDate DESC
  `;

  customerDB.all(sql, [customerId], (err, rows) => {
    if (err) {
      console.error('Invoice fetch error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    const results = rows.map(r => {
      const total = Number(r.Total);
      const paid = Number(r.Paid);
      let status = 'Unpaid';
      if (paid >= total) status = 'Paid';
      else if (paid > 0) status = 'Partial';

      return {
        InvoiceID: r.InvoiceID,
        InvoiceNumber: r.InvoiceNumber,
        InvoiceDate: r.InvoiceDate,
        status,
        balance: (total - paid).toFixed(2)
      };
    });

    res.json(results);
  });
});

// --- 3. Get Tracking for Specific Invoice ---
router.get('/invoice/:invoiceId/tracking', requirePortal, (req, res) => {
  const { invoiceId } = req.params;

  const invoiceSql = `
    SELECT
      i.InvoiceID,
      COALESCE((SELECT SUM(ii.TotalCost) FROM invoice_items ii WHERE ii.InvoiceID = i.InvoiceID), 0) AS Total,
      COALESCE((SELECT SUM(p.AmountPaid) FROM payments p WHERE p.InvoiceID = i.InvoiceID), 0) AS Paid
    FROM invoices i
    WHERE i.InvoiceID = ?
  `;

  customerDB.get(invoiceSql, [invoiceId], (err, inv) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!inv) return res.status(404).json({ error: 'Invoice not found' });

    const total = Number(inv.Total);
    const paid  = Number(inv.Paid);
    let status  = 'Unpaid';
    if (paid >= total) status = 'Paid';
    else if (paid > 0) status = 'Partial';

    // 🚫 Block if not fully paid
    if (status !== 'Paid') {
      return res.json({
        status,
        items: [],
        summary: null,
        message: 'Tracking is only available once invoice is fully paid.'
      });
    }

    // ✅ Fetch tracking when paid
    const itemsSql = `
      SELECT
        ii.ItemName,
        ii.Description,
        ii.Quantity,
        (SELECT t.Stage FROM tracking t WHERE t.ItemID = ii.ItemID ORDER BY t.Timestamp DESC LIMIT 1) AS LatestStage,
        (SELECT t.Timestamp FROM tracking t WHERE t.ItemID = ii.ItemID ORDER BY t.Timestamp DESC LIMIT 1) AS LastUpdate
      FROM invoice_items ii
      WHERE ii.InvoiceID = ?
    `;

    customerDB.all(itemsSql, [invoiceId], (err, items) => {
      if (err) return res.status(500).json({ error: 'Tracking DB error' });

      const steps = ['Picked up','Received (London)','Shipped','Arrived (Freetown)','Delivered'];
      const idxs = items
        .map(i => steps.indexOf(i.LatestStage || ''))
        .filter(i => i >= 0);
      const current = idxs.length ? Math.max(...idxs) : 0;

      res.json({ status, items, summary: { steps, current } });
    });
  });
});


// --- 4. Mock Pay Invoice Endpoint ---
// TODO: Replace mock logic with real Stripe/PayPal integration

// --- 4. Mock Pay Invoice Endpoint ---
router.post('/pay/:invoiceId', (req, res) => {
  const { invoiceId } = req.params;

  // Check invoice exists
  const sql = `
    SELECT InvoiceID, InvoiceNumber,
      COALESCE((SELECT SUM(ii.TotalCost) FROM invoice_items ii WHERE ii.InvoiceID = i.InvoiceID), 0) AS Total,
      COALESCE((SELECT SUM(p.AmountPaid) FROM payments p WHERE p.InvoiceID = i.InvoiceID), 0) AS Paid
    FROM invoices i
    WHERE i.InvoiceID = ?
  `;

  customerDB.get(sql, [invoiceId], (err, invoice) => {
    if (err) {
      console.error('Pay lookup error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (!invoice) {
      return res.status(404).json({ error: 'Invoice not found' });
    }

    const total = Number(invoice.Total);
    const paid = Number(invoice.Paid);
    const balance = total - paid;

    if (balance <= 0) {
      return res.json({ success: true, message: 'Invoice already paid' });
    }

    // --- Future: integrate Stripe Checkout here ---
    // Example:
    // const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
    // const session = await stripe.checkout.sessions.create({
    //   payment_method_types: ['card'],
    //   line_items: [{
    //     price_data: {
    //       currency: 'gbp',
    //       product_data: { name: `Invoice ${invoice.InvoiceNumber}` },
    //       unit_amount: balance * 100, // in pence
    //     },
    //     quantity: 1,
    //   }],
    //   mode: 'payment',
    //   success_url: 'http://localhost:3000/portal-invoices.html?paid=success',
    //   cancel_url: 'http://localhost:3000/portal-pay.html?cancelled=true',
    // });
    // return res.json({ url: session.url });

    // --- Mock response ---
    console.log(`✅ Mock payment for Invoice ${invoice.InvoiceNumber}, £${balance}`);
    res.json({ success: true, message: `Mock payment successful for Invoice ${invoice.InvoiceNumber}` });
  });
});

// GET referral credit for the logged-in portal customer
// GET referral credit for the logged-in portal customer
router.get('/:customerId/referral-credit', requirePortal, async (req, res) => {
  const { customerId } = req.params;

  // Ensure they can only view their own credit
  const sessionCustomerId = req.session.customerId;
  if (!sessionCustomerId || String(sessionCustomerId) !== String(customerId)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  try {
    const credit = await getReferralCreditForCustomer(customerId);
    res.json(credit);
  } catch (err) {
    console.error('Portal: failed to calculate referral credit', err);
    res.status(500).json({ error: 'Failed to calculate referral credit' });
  }
});


// POST: apply referral credit to an invoice (portal customer)
router.post('/:customerId/apply-referral-credit/:invoiceId', requirePortal, async (req, res) => {
  const { customerId, invoiceId } = req.params;

  // Ensure the logged-in portal user is the same as the URL customerId
  const sessionCustomerId = req.session.customerId;
  if (!sessionCustomerId || String(sessionCustomerId) !== String(customerId)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const rawAmount = req.body.amount;
  const requestedAmount = rawAmount ? parseFloat(rawAmount) : null;

  if (rawAmount && (!Number.isFinite(requestedAmount) || requestedAmount <= 0)) {
    return res.status(400).json({ error: 'Invalid credit amount' });
  }

  try {
    // 1) Load invoice and confirm it belongs to this customer + get current balance
    const invoice = await new Promise((resolve, reject) => {
      customerDB.get(`
        SELECT 
          i.InvoiceID,
          i.CustomerID,
          COALESCE((
            SELECT SUM(TotalCost) FROM invoice_items WHERE InvoiceID = i.InvoiceID
          ), 0) AS Subtotal,
          COALESCE((
            SELECT SUM(AmountPaid) FROM payments WHERE InvoiceID = i.InvoiceID
          ), 0) AS TotalPaid
        FROM invoices i
        WHERE i.InvoiceID = ?
      `, [invoiceId], (err, row) => {
        if (err) return reject(err);
        resolve(row);
      });
    });

    if (!invoice || String(invoice.CustomerID) !== String(customerId)) {
      return res.status(404).json({ error: 'Invoice not found' });
    }

    const balance = invoice.Subtotal - invoice.TotalPaid;
    if (balance <= 0) {
      return res.status(400).json({ error: 'Invoice has no outstanding balance' });
    }

    // 2) Get referral credit for this customer
    const credit = await getReferralCreditForCustomer(customerId);
    if (credit.available <= 0) {
      return res.status(400).json({ error: 'No referral credit available' });
    }

    // 3) Decide how much to apply (min of requested, available, and balance)
    let amountToApply = requestedAmount || credit.available;
    amountToApply = Math.min(amountToApply, credit.available, balance);

    if (!Number.isFinite(amountToApply) || amountToApply <= 0) {
      return res.status(400).json({ error: 'Nothing to apply' });
    }

    // 4) Insert a payment entry using referral credit
    await new Promise((resolve, reject) => {
      customerDB.run(`
        INSERT INTO payments (InvoiceID, AmountPaid, PaymentDate, PaymentMethod)
        VALUES (?, ?, date('now'), 'Referral Credit')
      `, [invoiceId, amountToApply], function (err) {
        if (err) return reject(err);
        resolve();
      });
    });

    // 5) Recalculate credit and balance to return to the portal
    const updatedCredit = await getReferralCreditForCustomer(customerId);
    const newBalance = balance - amountToApply;

    res.json({
      success: true,
      applied: amountToApply,
      remainingCredit: updatedCredit.available,
      newBalance
    });
  } catch (err) {
    console.error('Portal: failed to apply referral credit', err);
    res.status(500).json({ error: 'Failed to apply referral credit' });
  }
});



module.exports = router;
