const express = require('express');
const crypto = require('crypto');
const base64url = require('base64url');
const fs = require('fs');

const router = express.Router();
const SECRET_KEY = 'your_secret_key';
//const users = JSON.parse(fs.readFileSync('users.json', 'utf-8'));
const users = JSON.parse(fs.readFileSync('./src/data/users.json', 'utf-8'));

const session = require('express-session');

const JWT_COOKIE_NAME = 'jwt';

function createJWT(user) {

  console.log("In createJWT - input parm user -" + JSON.stringify(user));

  const header = { alg: 'HS256', typ: 'JWT' };

  const token =
    base64url.encode(JSON.stringify(header)) +
    '.' +
    base64url.encode(JSON.stringify(user));

  console.log("--> createJwt - header is " + base64url.encode(JSON.stringify(header)) );
  console.log("--> createJwt - payload is " + base64url.encode(JSON.stringify(user)) );
  console.log("--> createJwt - payload is " + JSON.stringify(user) );


  const signature = crypto
    .createHmac('sha256', SECRET_KEY)
    .update(token)
    .digest('hex');

  return token + '.' + base64url.encode(signature);
}

function verifyJWT(token) {

  console.log("In verifyJwt");
  if (!token) return false;
  
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  console.log("In verifyJwt2" + parts[0] + '^^^^^^' + token);

  const header = JSON.parse(base64url.decode(parts[0]));
  const payload = JSON.parse(base64url.decode(parts[1]));
  
  const signature = base64url.decode(parts[2]);
  console.log("In verifyJwt3 - w/payload - " + JSON.stringify(payload));
  console.log("In verifyJwt3 - w/payload - parts0 " + parts[0]);
  console.log("In verifyJwt3 - w/payload - parts1 " + parts[1]);

  const validSignature = crypto
    .createHmac('sha256', SECRET_KEY)
    .update(parts[0] + '.' + parts[1])
    .digest('hex');

  console.log("In verifyJwt4- valid sign - " + validSignature);
  console.log("In verifyJwt4- sign - " + signature);


  if (signature === validSignature && payload.exp > Math.floor(Date.now() / 1000))
  {return payload;}
  else 
  {return false};
}


function hashPassword(password, salt, iterations = 10000, keyLength = 64, digest = 'sha512') {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, iterations, keyLength, digest, (err, derivedKey) => {
      if (err) {
        reject(err);
      } else {
        resolve(derivedKey.toString('hex'));
      }
    });
  });
}


/*---
function validatePassword (pswd, salt,hpswd) {
console.log("In validate pwd " + pswd + salt);

(async () => {
	const pwd1 = pswd;
	const salt1 = salt;
	const hashedPassword = await hashPassword(pswd, salt1);
	console.log('------------------------------');
	console.log('Salt:', salt1);
	console.log('Hashed password:', hashedPassword);
	console.log('current phash: ', hpswd);
	
})();


};
---*/

function validatePassword(pswd, salt, hpswd) {
  return hashPassword(pswd, salt)
    .then(hashedPassword => {
      console.log('Hashed password:', hashedPassword);
      console.log('current phash: ', hpswd);
      if (hashedPassword !== hpswd) {
        console.log('In False');
        return 1;
      }
      console.log('In True');
      return 0;
    });
}


/*--
async function validatePassword (pswd, salt, hpswd) {

    const hashedPassword =  hashPassword(pswd, salt);
	console.log('Hashed password:', hashedPassword);
	console.log('current phash: ', hpswd);
	
    if (hashedPassword !== hpswd) {

		console.log('In False');
        return 1;

    }
    
	console.log('In True');

    return 0;
}
--*/


function printdttm () {

	var today = new Date();
	var date = today.getFullYear()+'-'+(today.getMonth()+1)+'-'+today.getDate();
	var	time = today.getHours() + ":" + today.getMinutes() + ":" + today.getSeconds();
	var dateTime = date+' '+time;

	console.log(dateTime)

};

function authMiddleware(req, res, next) {

  console.log ("In authMiddleware");
  try {
    const jwt = req.cookies[JWT_COOKIE_NAME];
//console.log("---> 5b. I am in authMiddleware - retrieving jwt - " + jwt);

//    if (!jwt) throw new Error('Unauthenticated user');
    if (!jwt) {res.redirect('/login');};
    const payload = verifyJWT(jwt);
    
    console.log ("return value from verifyjwt " + payload);
    
    if (payload === false ) 
    {console.log("In false rtn ");
    res.redirect('/login');
    }
    else 
    {console.log("In non-false rtn ");};
    
    req.username = payload.user.username;
    req.user = payload.user;

    console.log("---> 5c. I am in authMiddleware" + JSON.stringify(payload) + '--' + JSON.stringify(payload.user));
//    res.send(req.user);
    next();
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
}

function dispcurrentuser(req, res, next) {

  console.log ("In dispcurrentuser");
  try {
    const jwt = req.cookies[JWT_COOKIE_NAME];
//console.log("---> 5b. I am in authMiddleware - retrieving jwt - " + jwt);

//    if (!jwt) throw new Error('Unauthenticated user');
    if (!jwt) {res.redirect('/login');};
    const payload = verifyJWT(jwt);
    req.user = payload.user;

    console.log("---> 5c. I am in dispcurrentuser" + JSON.stringify(payload) + '--' + JSON.stringify(payload.user));
    res.send(req.user);
    next();
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
}

//dispcurrentuser
// Middleware to ensure user is authenticated
function requireLogin(req, res, next) {

  console.log ("In requirelogin1");
  printdttm();

  if (req.session.user) {
    next();
  } else {
    res.redirect('/login');
  }
  
}

router.get('/', authMiddleware, (req, res) => {
  printdttm();

  const username = req.username;
  console.log ("In app.get / " + JSON.stringify(username) + '_' + JSON.stringify(users));
  const user = users.find((u) => u.username === username);

  console.log ("In get / -- user is -" + JSON.stringify(user));
  res.render('home', { user });
});

// Login page routes
router.get('/login', (req, res) => {
  printdttm();

  console.log ("In router.get /login");

  res.render('login');
});

router.post('/login', (req, res) => {

	printdttm();

	console.log ("In router.post /login");

	const { username, password } = req.body;
	console.log ("user pass is " + username + password);

	console.log("___req user is " + username);
	console.log("___After req user is " + username);

	//  const user = users.find((u) => u.username === username && u.password === password);
	const user = users.find((u) => u.username === username);
	console.log ("This is the user id123 " + JSON.stringify(user));
	if (!user) {
	return res.status(401).json({ error: 'Invalid email or password' });
	}

	const usalt = user.salt;
	const userInfo = {
	id: user.id,
	first_name: user.firstName,
	last_name: user.lastName,
	username: user.username
	};

	let valid_pswd = 0;

/*--
	console.log("-> 4.1 Before validatepassword " + valid_pswd);

	valid_pswd = await validatePassword (password,usalt, user.password);
	console.log("-> 4.2 After validatepassword " + JSON.stringify(valid_pswd));
--*/

	validatePassword(password, usalt, user.password)
	.then(valid_pswd => {
	if (valid_pswd == 0) {
			console.log("-> After validatepassword " + JSON.stringify(valid_pswd));
		}
		else {
			console.log("-> In incorrect - validatepassword " + JSON.stringify(valid_pswd));
			res.json({"err":"Incorrect password entered"});

//			res.json("Incorrect password used. re-try");
		}
	})
	.catch(err => {
	console.error(err);
	

	});

/*--
	if (valid_pswd == 1) 
	{console.log("-> Incorrect password " + password);
	return res.status(400).send("Incorrect password used. re-try")
	}
	;
--*/
	const payload = {
	user: userInfo,
	exp: Math.floor(Date.now() / 1000) + 120, // Expires in 1 hour
	};

	const jwt = createJWT(payload);
	console.log("I am in post /login - " + JSON.stringify(payload) + '==' + jwt);

	res.cookie(JWT_COOKIE_NAME, jwt, { httpOnly: true });
	console.log("I am in post /login - b4 send json - " + JSON.stringify(payload )); 
	res.render('home', { user });

});

// Logout route
router.get('/logout', (req, res) => {
  printdttm();

  console.log ("In router.get /logout");

  req.session.destroy();
  res.redirect('/login');
});



// Logout route
router.post('/logout', (req, res) => {
  printdttm();

  console.log ("In router.post /logout");

  res.clearCookie(JWT_COOKIE_NAME);
  res.redirect('/');

});

router.get('/users/current', dispcurrentuser, (req, res) => {

   printdttm();

});

module.exports = router;
