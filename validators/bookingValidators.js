const { body, param, query, validationResult } = require('express-validator');

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

/* -------------------------
   BOOKINGS
--------------------------*/

// GET /bookings/:customerId
exports.validateCustomerIdParam = [
  param('customerId')
    .isInt({ min: 1 }).withMessage('Invalid customer ID'),
  handleValidationResult
];

// POST /bookings/:customerId  (create)
exports.validateBookingCreate = [
  param('customerId')
    .isInt({ min: 1 }).withMessage('Invalid customer ID'),

  body('AfternoonEvening')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 50 }).withMessage('Afternoon/Evening value too long'),

  body('BookingDate')
    .notEmpty().withMessage('BookingDate is required')
    .bail()
    .trim()
    .isLength({ max: 20 }).withMessage('BookingDate too long'),

  body('BookingSlot')
    .optional({ checkFalsy: true })
    .toInt()
    .isInt({ min: 1, max: 9 }).withMessage('BookingSlot must be between 1 and 9'),

  body('Notes')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 1000 }).withMessage('Notes too long'),

  body('Status')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 50 }).withMessage('Status too long'),

  handleValidationResult
];

// PUT /bookings/:bookingId  (update)
exports.validateBookingUpdate = [
  param('bookingId')
    .isInt({ min: 1 }).withMessage('Invalid booking ID'),

  body('AfternoonEvening')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 50 }).withMessage('Afternoon/Evening value too long'),

  body('BookingDate')
    .notEmpty().withMessage('BookingDate is required')
    .bail()
    .trim()
    .isLength({ max: 20 }).withMessage('BookingDate too long'),

  body('BookingSlot')
    .notEmpty().withMessage('BookingSlot is required')
    .bail()
    .toInt()
    .isInt({ min: 1, max: 9 }).withMessage('BookingSlot must be between 1 and 9'),

  body('Notes')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 1000 }).withMessage('Notes too long'),

  body('Status')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 50 }).withMessage('Status too long'),

  handleValidationResult
];

// PUT /bookings/:bookingId/slot
exports.validateBookingSlotUpdate = [
  param('bookingId')
    .isInt({ min: 1 }).withMessage('Invalid booking ID'),

  body('BookingSlot')
    .notEmpty().withMessage('BookingSlot is required')
    .bail()
    .toInt()
    .isInt({ min: 1, max: 9 }).withMessage('BookingSlot must be between 1 and 9'),

  handleValidationResult
];

// DELETE /bookings/:bookingId
exports.validateBookingDelete = [
  param('bookingId')
    .isInt({ min: 1 }).withMessage('Invalid booking ID'),
  handleValidationResult
];

/* -------------------------
   ALLOCATIONS
--------------------------*/

// GET /api/allocations/:bookingId
exports.validateAllocationGet = [
  param('bookingId')
    .isInt({ min: 1 }).withMessage('Invalid booking ID'),
  handleValidationResult
];

// GET /api/bookings-to-allocate?date=&region=&slot=
exports.validateBookingsToAllocateQuery = [
  query('date')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 20 }).withMessage('Date filter too long'),

  query('region')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 50 }).withMessage('Region filter too long'),

  query('slot')
    .optional({ checkFalsy: true })
    .toInt()
    .isInt({ min: 1, max: 9 }).withMessage('Slot filter must be between 1 and 9'),

  handleValidationResult
];

// POST /allocate-job (single allocation)
exports.validateAllocationSingle = [
  body('BookingID')
    .notEmpty().withMessage('BookingID is required')
    .bail()
    .toInt()
    .isInt({ min: 1 }).withMessage('BookingID must be a positive integer'),

  body('DriverName')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 100 }).withMessage('Driver name too long'),

  body('Helper1Name')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 100 }).withMessage('Helper1 name too long'),

  body('Helper2Name')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 100 }).withMessage('Helper2 name too long'),

  body('Van')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 100 }).withMessage('Van name too long'),

  body('Notes')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 500 }).withMessage('Notes too long'),

  handleValidationResult
];

// POST /allocate-jobs-batch (array of allocations)
exports.validateAllocationBatch = [
  body()
    .isArray({ min: 1 }).withMessage('Allocations payload must be a non-empty array'),

  body('*.BookingID')
    .notEmpty().withMessage('BookingID is required')
    .bail()
    .toInt()
    .isInt({ min: 1 }).withMessage('BookingID must be a positive integer'),

  body('*.DriverName')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 100 }).withMessage('Driver name too long'),

  body('*.Helper1Name')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 100 }).withMessage('Helper1 name too long'),

  body('*.Helper2Name')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 100 }).withMessage('Helper2 name too long'),

  body('*.Van')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 100 }).withMessage('Van name too long'),

  body('*.Notes')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 500 }).withMessage('Notes too long'),

  handleValidationResult
];
