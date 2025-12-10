const { body, param, validationResult } = require('express-validator');

exports.validateCustomer = [

  // Name
  body('FirstName')
    .trim()
    .notEmpty().withMessage('First name is required')
    .isLength({ max: 100 }).withMessage('First name too long'),

  body('LastName')
    .trim()
    .notEmpty().withMessage('Last name is required')
    .isLength({ max: 100 }).withMessage('Last name too long'),

  // Optional fields (validate if present)
  body('Company')
    .optional()
    .trim()
    .isLength({ max: 150 }),

  body('Address1')
    .optional()
    .trim()
    .isLength({ max: 255 }),

  body('Address2')
    .optional()
    .trim()
    .isLength({ max: 255 }),

  body('PostCode')
    .trim()
    .notEmpty().withMessage('Postcode is required')
    .isLength({ max: 20 }),

  body('Phone1')
    .optional()
    .trim()
    .isLength({ max: 30 }),

  body('Phone2')
    .optional()
    .trim()
    .isLength({ max: 30 }),

  body('Phone3')
    .optional()
    .trim()
    .isLength({ max: 30 }),

  // City / Country / Email
  body('Email')
    .optional()
    .trim()
    .isEmail().withMessage('Invalid email format')
    .normalizeEmail(),

  body('Country')
    .optional()
    .trim()
    .isLength({ max: 100 }),

  // Type & Category
  body('Type')
    .optional()
    .isIn(['Customer', 'Business']).withMessage('Invalid customer type'),

  body('Category')
    .optional()
    .isIn(['London', 'North', 'South', 'South-West', 'Freetown', 'Other'])
    .withMessage('Invalid category'),

  // Final error handler
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
