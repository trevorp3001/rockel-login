const { body, param, validationResult } = require('express-validator');

// Common error handler for this module
function handleValidationResult(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      errors: errors.array()
    });
  }
  next();
}

// GET /invoice-items/:invoiceId
// GET /api/invoice-items-with-tracking/:invoiceId
exports.validateInvoiceIdParam = [
  param('invoiceId')
    .isInt({ min: 1 }).withMessage('Invalid invoice ID'),
  handleValidationResult
];

// POST /invoice-items/:invoiceId  (create)
exports.validateInvoiceItemCreate = [
  param('invoiceId')
    .isInt({ min: 1 }).withMessage('Invalid invoice ID'),

  body('ItemName')
    .trim()
    .notEmpty().withMessage('Item name is required')
    .isLength({ max: 150 }).withMessage('Item name too long'),

  body('Description')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 500 }).withMessage('Description too long'),

  body('Quantity')
    .notEmpty().withMessage('Quantity is required')
    .bail()
    .isInt({ min: 1 }).withMessage('Quantity must be a positive integer'),

  body('UnitCost')
    .notEmpty().withMessage('UnitCost is required')
    .bail()
    .isFloat({ min: 0 }).withMessage('UnitCost must be a non-negative number'),

  body('ContainerID')
    .optional({ checkFalsy: true })
    .isInt({ min: 1 }).withMessage('ContainerID must be a positive integer'),

  handleValidationResult
];

// PUT /invoice-items/:itemId  (update)
exports.validateInvoiceItemUpdate = [
  param('itemId')
    .isInt({ min: 1 }).withMessage('Invalid item ID'),

  body('ItemName')
    .trim()
    .notEmpty().withMessage('Item name is required')
    .isLength({ max: 150 }).withMessage('Item name too long'),

  body('Description')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 500 }).withMessage('Description too long'),

  body('Quantity')
    .notEmpty().withMessage('Quantity is required')
    .bail()
    .isInt({ min: 1 }).withMessage('Quantity must be a positive integer'),

  body('UnitCost')
    .notEmpty().withMessage('UnitCost is required')
    .bail()
    .isFloat({ min: 0 }).withMessage('UnitCost must be a non-negative number'),

  handleValidationResult
];

// DELETE /invoice-items/:itemId
exports.validateInvoiceItemDelete = [
  param('itemId')
    .isInt({ min: 1 }).withMessage('Invalid item ID'),
  handleValidationResult
];
