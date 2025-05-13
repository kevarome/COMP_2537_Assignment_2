//requirements - what needs to be installed for this code to work
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const MongoStore = require('connect-mongo');
const session = require('express-session');
const Joi = require("joi");

//rounds for hashing
const saltRounds = 12;

//port listening
const port = process.env.PORT || 3000;

const app = express();


//When the session expires
const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

//to connect ot database
const {database} = require('./databaseConnection');

//users collection in database
const userCollection = database.db(mongodb_database).collection('users');

//require for parsing
app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}));

//Homepage which has the signup and login options. 
//If logged it, it redirects to members page
app.get('/', (req, res) => {
    var username = req.query.user;
    if (!username) {
        var html = `
        <body>
            <form action="/signup" method="get" style="display: inline;">
                <button type="submit" style="margin-right: 10px;">Sign up</button>
            </form>
            <form action="/login" method="get" style="display: inline;">
                <button type="submit">Log in</button>
            </form>
        </body>
        `;
    } else {
        res.redirect('./members');
    }
    res.send(html);
});

//nosql injection protects against alteration of query
app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/signup', (req, res) => {
    var html = `
            <body>
            <p>Create an account</p>
                <hr style="border: 1px solid black;">
            <form action="/signupSubmit" method="post">
                <input type="text" name="username" placeholder="Name" /><br><br>
                <input type="email" name="email" placeholder="Email" /><br><br>
                <input type="password" name="password" placeholder="Password" /><br><br>
                <button type="submit">Submit</button>
            </form>
            <div style="height: 40px;"></div>
        </body>
    `;
    res.send(html);
});

//When signing up we use joi for proper inputs and hash the password using bcrypt
app.post('/signupSubmit', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;
    var email = req.body.email;

    if (!username) {
        res.send(`<p>Name is required.</p><a href="/signup">Try again</a>`);
    } else if (!email) {
        res.send(`<p>Email is required.</p><a href="/signup">Try again</a>`);
    } else if (!password) {
        res.send(`<p>Password is required.</p><a href="/signup">Try again</a>`);
    } else {
        const schema = Joi.object(
            {
                username: Joi.string().alphanum().max(20).required(),
                password: Joi.string().max(20).required(),
                email: Joi.string().email().max(100).required()
            });
        
        const validationResult = schema.validate({username, email, password});
        if (validationResult.error != null) {
           console.log(validationResult.error);
           res.redirect("/signup");
           return;
       }
    
        var hashedPassword = await bcrypt.hash(password, saltRounds);
        
        await userCollection.insertOne({username: username, email: email, password: hashedPassword});

        req.session.authenticated = true;
        req.session.username = username;

        res.redirect("/members");
    }
});

//Login page
app.get('/login', (req,res) => {
    var html = `
    <body>
        <p>Log in </p>
        <hr style="border: 1px solid black;">
            <form action="/loginSubmit" method="post">
                <input name="email" type="email" placeholder="email"><br><br>
                <input name="password" type="password" placeholder="password"><br><br>
                <button type="submit">Submit</button>
            </form>

            <div style="height: 40px;"></div>
    </body>
    `;



    res.send(html);
});

//When logging in authenticate with database and validate credentials using joi
app.post('/loginSubmit', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.object({
        email: Joi.string().email().max(100).required(),
        password: Joi.string().max(20).required()
    });
	const validationResult = schema.validate({ email, password });
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, _id: 1}).toArray();

	if (result.length != 1) {
		res.send(`<p>Invalid email/password combination</p><a href="/login">Try again</a>`);
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		req.session.authenticated = true;
		req.session.username = result[0].username;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
	}
	else {
		res.send(`<p>Invalid email/password combination</p><a href="/login">Try again</a>`);
		return;
	}
});

//Members page. Making sure that they are valid users in database and displays random img
app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    var username = req.session.username;

    var img = ['dog1.png', 'dog2.png', 'dog3.png'];
    var randomImg = img[Math.floor(Math.random() * img.length)];

    var html = `
        <p>Hello, ${username}.</p>
        <br>
        <img src="/${randomImg}" alt="randomImg" style="max-width:250px;">
        <br>
        <br>
        <form action="/logout" method="get">
            <button type="submit">Sign out</button>
        </form>

    `;

    res.send(html);
});

app.use(express.static(__dirname + "/public"));

//logout destroys session and redirects to sign up/login page
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

//catch all for pages that dont exist
app.get("*dummy", (req,res) => {
    res.status(404);
    res.send("Page not found - 404");
});

//port listening
app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 