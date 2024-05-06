require("./utils.js");

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const Joi = require('joi');

const bcrypt = require('bcrypt');
const saltRounds = 12;

require('dotenv').config();

const app = express();

app.use(express.urlencoded({ exteded: false }));

const port = process.env.PORT || 3000;

const expireTime = 1 * 60 * 60 * 1000;

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
});


app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}
));

app.get('/', async (req, res) => {
    if (!req.session.authenticated) {
        var html = `
        <form action='/signup' method='post'>
            <button>Sign Up</button>
        </form>
        <form action='/login' method='post'>
            <button>Login</button>
        </form>
        `;

        res.send(html);
    } else {
        var html = `Welcome, ` + req.session.username +
            `
                    <form action='/members' method='post'>
                        <button>Go to members area!</button>
                    </form>
                    <form action='/logout' method='post'>
                        <button>Log out</button>
                    </form>
                    `;

        res.send(html);
    }

});

app.post('/signup', (req, res) => {
    res.redirect('/signup');
});

app.get('/signup',async (req, res) => {
    var missingField = req.query.missing;

    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'><br>
    <input name='email' type='email' placeholder='email'><br>
    <input name='password' type='password' placeholder='password'><br>
    <button>Submit</button>
    </form>
    `;

    if (missingField === 'username') {
        html += "<br> Username is required";
    }

    if (missingField === 'email') {
        html += "<br> Email is required";
    }

    if (missingField === 'password') {
        html += "<br> Password is required";
    }

    res.send(html);
});


app.post('/login', (req, res) => {
    res.redirect('/login');
});

app.get('/login', async (req, res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='email' placeholder='email'><br>
    <input name='password' type='password' placeholder='password'><br>
    <button>Submit</button>
    </form>
    `;

    res.send(html);
});


app.post('/submitUser', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;



    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } }).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ username, email, password });
    if (validationResult.error != null) {
        const missingField = validationResult.error.details[0].context.key;
        res.redirect(`/signup?missing=${missingField}`);
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ username: username, email: email, password: hashedPassword });


    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});


app.post('/loggingin', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    const emailSchema = Joi.string().email().required();
    const emailValidationResult = emailSchema.validate(email);
    if (emailValidationResult.error != null) {
        console.log(emailValidationResult.error);
        res.send("Invalid email format");
        return;
    }

    const result = await userCollection.find({ email: email }).project({username: 1, password: 1, _id: 1 }).toArray();

    if (result.length != 1) {
        res.redirect("/loginInvalid");
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
        res.redirect("/loginInvalid");
        return;
    }
});

app.get('/loginInvalid', async (req, res) => {
    var html = `Invalid email/password combination
    <form action='/login' method='post'>
        <button>Try again</button>
    </form>
    `;
    res.send(html);
})


app.post('/members', (req, res) => {
    res.redirect('/members');
});


function getRandomInt(max) {
    return Math.floor(Math.random() * max);
}

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    }
    randomValue = getRandomInt(3);
    var html = `<h1> Hello, ` + req.session.username + `</h1>`;

    if (randomValue == 0) {
        html += `<img src='/happycat.gif' style=width250px;><br>`;
    } else if (randomValue == 1) {
        html += `<img src='/kissingcat.gif' style=width250px;><br>`;
    } else if (randomValue == 2) {
        html += `<img src='/confusedcat.gif' style=width250px;><br>`;
    }

    html += `<form action='/logout' method='post'>
                <button>Log out</button>
            </form>`;

    res.send(html);
});


app.post('/logout', async (req, res) => {
    res.redirect('/logout');
})

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    var html = `Error 404 - Page not found <br>
    <img src='/404cat.jpg' style=width250px;>
    `;
    res.send(html);
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

