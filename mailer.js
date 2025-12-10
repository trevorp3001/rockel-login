// mailer.js
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'rockelshippingcompany@gmail.com',
    pass: 'sqfi qdha uubt pknm' // app password
  },
  tls: {
    rejectUnauthorized: false
  }
});

// ✨ Now accepts optional attachments
function sendMail(to, subject, text = '', html = '', attachments = []) {
  const mailOptions = {
    from: '"Rockel Shipping" <rockelshippingcompany@gmail.com>',
    to,
    subject,
    text,
    html,
    attachments // 📎 array of files { filename, path }
  };

  return transporter.sendMail(mailOptions);
}

module.exports = sendMail;
