const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const base64url = require('base64url');
const fs = require('fs');

const app = express();

app.set('view engine', 'ejs');


const session = require('express-session');

app.use(
  session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // Set to true for HTTPS connections
  })
);

app.use(express.static('templates'));

const routes = require('./src/routes');

app.use(bodyParser.urlencoded({ extended: true }));

app.use(cookieParser());
app.use(routes);

app.set('view engine', 'ejs');


const SECRET_KEY = 'your_secret_key';
const users = JSON.parse(fs.readFileSync('./src/data/users.json', 'utf-8'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});



