const { body, param, validationResult } = require('express-validator');

// Shared error handler
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

/* ----------------------------------------
   PARAM VALIDATION
---------------------------------------- */

exports.validateItemIdParam = [
  param('itemId')
    .toInt()
    .isInt({ min: 1 }).withMessage('Invalid item ID'),
  handleValidationResult
];

exports.validateTrackingIdParam = [
  param('trackingId')
    .toInt()
    .isInt({ min: 1 }).withMessage('Invalid tracking ID'),
  handleValidationResult
];

exports.validateTrackingIdDelete = [
  param('id')
    .toInt()
    .isInt({ min: 1 }).withMessage('Invalid tracking ID'),
  handleValidationResult
];

/* ----------------------------------------
   POST /track-item/:itemId
---------------------------------------- */

exports.validateTrackingCreate = [

  body('Stage')
    .trim()
    .notEmpty().withMessage('Stage is required')
    .isLength({ max: 50 }).withMessage('Stage too long'),

  body('Timestamp')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 40 }).withMessage('Timestamp too long'),

  body('Location')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 200 }).withMessage('Location too long'),

  body('Notes')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 1000 }).withMessage('Notes too long'),

  body('ContainerID')
    .optional({ checkFalsy: true })
    .toInt()
    .isInt({ min: 1 }).withMessage('Invalid container ID'),

  body('SignatureData')
    .optional({ checkFalsy: true })
    .isString().withMessage('Invalid signature format'),

  handleValidationResult
];

/* ----------------------------------------
   PUT /track-item/update/:trackingId
---------------------------------------- */

exports.validateTrackingUpdate = [
  body('Stage')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 50 }).withMessage('Stage too long'),

  body('Timestamp')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 40 }).withMessage('Timestamp too long'),

  body('Notes')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 1000 }).withMessage('Notes too long'),

  body('Location')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 200 }).withMessage('Location too long'),

  body('ContainerID')
    .optional({ checkFalsy: true })
    .toInt()
    .isInt({ min: 1 }).withMessage('Invalid container ID'),

  body('SignatureData')
    .optional({ checkFalsy: true })
    .isString().withMessage('Invalid signature'),

  handleValidationResult
];

/* ----------------------------------------
   POST /api/track-item/:itemId
---------------------------------------- */

exports.validateQuickTrack = [
  body('Stage')
    .trim()
    .notEmpty().withMessage('Stage required')
    .isLength({ max: 50 }),

  body('ContainerID')
    .optional({ checkFalsy: true })
    .toInt()
    .isInt({ min: 1 }),

  body('Notes')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 1000 }),

  handleValidationResult
];
