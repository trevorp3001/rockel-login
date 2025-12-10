// auth_middleware.js

/**
 * MAIN DB (index.html / customer.html)
 */
function requireAuth(req, res, next) {
  // Main DB session
  if (req.session && req.session.mainAuthenticated && req.session.mainUser) {
    return next();
  }

  // Backwards-compatibility for old sessions that still use user/authenticated
  if (req.session && req.session.authenticated && req.session.user) {
    return next();
  }

  // If request is expecting JSON (fetch/XHR), send 401 JSON
  const wantsJson =
    req.xhr ||
    (req.headers.accept && req.headers.accept.indexOf('json') !== -1);

  if (wantsJson) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Otherwise, redirect to main login
  return res.redirect('/');
}

/**
 * STAFF / ADMIN (staff-login.html / admin-dashboard.html)
 * Uses its own flags: staffAuthenticated + staffUser
 */
function requireStaff(req, res, next) {
  if (req.session && req.session.staffAuthenticated && req.session.staffUser) {
    return next();
  }

  const wantsJson =
    req.xhr ||
    (req.headers.accept && req.headers.accept.indexOf('json') !== -1);

  if (wantsJson) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  return res.redirect('/staff-login.html');
}

/**
 * ADMIN check – allows either:
 * - main admin (mainUser.role === 'Admin'), or
 * - staff admin (staffUser.role === 'Admin')
 */
function requireAdmin(req, res, next) {
  const mainUser = req.session && req.session.mainUser;
  const staffUser = req.session && req.session.staffUser;

  const mainIsAuthed =
    !!(req.session && req.session.mainAuthenticated && mainUser);
  const staffIsAuthed =
    !!(req.session && req.session.staffAuthenticated && staffUser);

  const role =
    (staffUser && (staffUser.role || staffUser.Role)) ||
    (mainUser && (mainUser.role || mainUser.Role)) ||
    null;

  if ((mainIsAuthed || staffIsAuthed) && role === 'Admin') {
    return next();
  }

  const wantsJson =
    req.xhr ||
    (req.headers.accept && req.headers.accept.indexOf('json') !== -1);

  if (wantsJson) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  return res.redirect('/index.html');
}

/**
 * CUSTOMER PORTAL (portal-login.html / portal-*.html)
 * You already had something like this; keep your logic.
 */
function requirePortal(req, res, next) {
  if (req.session && req.session.portalAuthenticated && req.session.portalUser) {
    return next();
  }

  const wantsJson =
    req.xhr ||
    (req.headers.accept && req.headers.accept.indexOf('json') !== -1);

  if (wantsJson) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  return res.redirect('/portal-login.html');
}

module.exports = {
  requireAuth,
  requireAdmin,
  requirePortal,
  requireStaff,
};
