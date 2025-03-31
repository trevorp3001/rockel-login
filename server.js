const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const app = express();
const port = 3000;

// Dummy user for testing
const user = {
  username: 'admin',
  password: 'password123' // In production, hash this!
};

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public')); // to serve the login page

// Serve login page (optional if you open HTML directly)
app.get('/', (req, res) => {
  res.sendFile(__dirname + 'public/index.html');
});

// Handle login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  if (username === user.username && password === user.password) {
    res.send(`<h2>Welcome, ${username}!</h2><p>Login successful.</p>`);
  } else {
    res.send('<h2>Login failed</h2><p>Invalid username or password.</p>');
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
