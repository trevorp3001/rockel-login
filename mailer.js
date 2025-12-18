// mailer.js
require('dotenv').config();
const nodemailer = require('nodemailer');

// Create transporter using ENV variables
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,                  // e.g. smtp.gmail.com
  port: Number(process.env.EMAIL_PORT) || 465,   // 465 for secure, 587 for TLS
  secure: process.env.EMAIL_SECURE === 'true',   // convert string to boolean
  auth: {
    user: process.env.EMAIL_USER,                // your gmail address
    pass: process.env.EMAIL_PASS                 // your app password
  },
  tls: {
    rejectUnauthorized: false
  }
});

// Send mail with optional attachments
function sendMail(to, subject, text = '', html = '', attachments = []) {
  const mailOptions = {
    from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
    to,
    subject,
    text,
    html,
    attachments
  };

  return transporter.sendMail(mailOptions);
}

module.exports = sendMail;
