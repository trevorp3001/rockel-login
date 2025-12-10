const { body, param, validationResult } = require('express-validator');

// Common fields used on both create + update
const invoiceCommonFields = [
  body('InvoiceDate')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 20 }).withMessage('Invoice date too long'),

  body('ReceiverName')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 150 }).withMessage('Receiver name too long'),

  body('Email')
    .optional({ checkFalsy: true })
    .trim()
    .isEmail().withMessage('Invalid email format')
    .normalizeEmail(),

  body('Phone1')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 30 }).withMessage('Phone1 too long'),

  body('Phone2')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 30 }).withMessage('Phone2 too long'),

  body('Phone3')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 30 }).withMessage('Phone3 too long'),

  body('Address1')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 255 }).withMessage('Address1 too long'),

  body('Address2')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 255 }).withMessage('Address2 too long'),

  body('PostCode')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 20 }).withMessage('Postcode too long'),

  body('Country')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 100 }).withMessage('Country too long'),

  body('Notes')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 1000 }).withMessage('Notes too long'),

  body('Delivery')
    .optional({ checkFalsy: true })
    .custom(v => {
      // allow '0' / '1' / 0 / 1 / true / false-ish
      if (v === undefined || v === null || v === '') return true;
      if (v === '0' || v === '1' || v === 0 || v === 1) return true;
      return false;
    })
    .withMessage('Invalid delivery flag')
];

// CREATE: POST /invoices/:customerId
exports.validateInvoiceCreate = [
  param('customerId')
    .isInt({ min: 1 }).withMessage('Invalid customer ID'),

  ...invoiceCommonFields,

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }
    next();
  }
];

// UPDATE: POST /invoices/update/:invoiceId
exports.validateInvoiceUpdate = [
  param('invoiceId')
    .isInt({ min: 1 }).withMessage('Invalid invoice ID'),

  ...invoiceCommonFields,

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }
    next();
  }
];

// PAYMENT: POST /invoice-payments/:invoiceId
exports.validateInvoicePayment = [
  param('invoiceId')
    .isInt({ min: 1 }).withMessage('Invalid invoice ID'),

  body('AmountPaid')
    .notEmpty().withMessage('AmountPaid is required')
    .bail()
    .isFloat({ gt: -0.00001 }).withMessage('AmountPaid must be a valid number'),

  body('PaymentDate')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 20 }).withMessage('Payment date too long'),

  body('PaymentMethod')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 50 }).withMessage('Payment method too long'),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }
    next();
  }
];
