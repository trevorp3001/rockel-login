// validators/staffValidators.js

function normalizeUsername(username) {
  if (typeof username !== 'string') return '';
  return username.trim();
}

function validatePasswordStrength(password) {
  if (typeof password !== 'string') return 'Password is required';

  const pwd = password.trim();
  if (pwd.length < 8) {
    return 'Password must be at least 8 characters long.';
  }

  // Optional basic complexity: at least one letter and one digit
  const hasLetter = /[A-Za-z]/.test(pwd);
  const hasDigit = /\d/.test(pwd);

  if (!hasLetter || !hasDigit) {
    return 'Password must contain at least one letter and one number.';
  }

  return null; // no error
}

/**
 * ✅ validateStaffLogin
 * Used for POST /api/staff/login (if you decide to plug it in)
 */
function validateStaffLogin(req, res, next) {
  const errors = [];
  let { username, password } = req.body || {};

  username = normalizeUsername(username);

  if (!username) {
    errors.push('Username is required.');
  } else if (username.length < 3 || username.length > 50) {
    errors.push('Username must be between 3 and 50 characters.');
  }

  if (!password || typeof password !== 'string' || password.trim().length < 6) {
    errors.push('Password is required and must be at least 6 characters.');
  }

  if (errors.length > 0) {
    return res.status(400).json({ error: errors.join(' ') });
  }

  req.body.username = username;
  return next();
}

/**
 * ✅ validateStaffCreate
 * Used for POST /api/staff-users (creating a new staff account)
 */
function validateStaffCreate(req, res, next) {
  const errors = [];
  let { username, password, role } = req.body;

  username = normalizeUsername(username);

  // Username checks
  if (!username) {
    errors.push('Username is required.');
  } else if (username.length < 3 || username.length > 50) {
    errors.push('Username must be between 3 and 50 characters.');
  }

  // Role checks
  const allowedRoles = ['Admin', 'Staff'];
  if (!role || !allowedRoles.includes(role)) {
    errors.push('Role must be either "Admin" or "Staff".');
  }

  // Password checks (required on create)
  const pwdError = validatePasswordStrength(password);
  if (pwdError) {
    errors.push(pwdError);
  }

  if (errors.length > 0) {
    return res.status(400).json({ error: errors.join(' ') });
  }

  // Normalise values back into req.body
  req.body.username = username;
  req.body.role = role;
  req.body.password = password.trim();

  return next();
}

/**
 * ✅ validateStaffUpdate
 * Used for PUT /api/staff-users/:id (editing an existing staff account)
 * - Username + role required
 * - Password optional; if provided, must be strong
 */
function validateStaffUpdate(req, res, next) {
  const errors = [];
  let { username, role, password } = req.body;

  username = normalizeUsername(username);

  if (!username) {
    errors.push('Username is required.');
  } else if (username.length < 3 || username.length > 50) {
    errors.push('Username must be between 3 and 50 characters.');
  }

  const allowedRoles = ['Admin', 'Staff'];
  if (!role || !allowedRoles.includes(role)) {
    errors.push('Role must be either "Admin" or "Staff".');
  }

  // Password is OPTIONAL on update. Only validate if provided.
  if (password && password.trim() !== '') {
    const pwdError = validatePasswordStrength(password);
    if (pwdError) {
      errors.push(pwdError);
    } else {
      req.body.password = password.trim();
    }
  } else {
    // Explicitly normalise to empty string when "keep existing"
    req.body.password = '';
  }

  if (errors.length > 0) {
    return res.status(400).json({ error: errors.join(' ') });
  }

  req.body.username = username;
  req.body.role = role;

  return next();
}

/**
 * ✅ validateStaffPasswordReset
 * For any future password-reset endpoint you add.
 */
function validateStaffPasswordReset(req, res, next) {
  const { password } = req.body;
  const pwdError = validatePasswordStrength(password);

  if (pwdError) {
    return res.status(400).json({ error: pwdError });
  }

  req.body.password = password.trim();
  return next();
}

module.exports = {
  validateStaffLogin,
  validateStaffCreate,
  validateStaffUpdate,
  validateStaffPasswordReset
};
