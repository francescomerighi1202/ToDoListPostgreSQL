import express from 'express';
import session from 'express-session';
import flash from 'express-flash';
import bcrypt from 'bcrypt';
import pg from 'pg';
import passport from 'passport';
import LocalStrategy from 'passport-local';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Express app configuration
const app = express();
const port = process.env.PORT || 3000;

// Database client connection
const db = new pg.Client({
    user: 'postgres',
    password: process.env.DB_PW,
    host: 'localhost',
    port: 5432,
    database: 'todo-list'
});

// General middlewares
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(flash());

app.use(session({
    secret: process.env.SESSION,
    resave: false,
    saveUninitialized: false
}));

// Passport.js middlewares for authentication
app.use(passport.initialize());
app.use(passport.session());

// Passport.js local configuration
passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, async (email, password, done) => {
    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        // If user not found show error message
        if (!user) {
            return done(null, false, { message: 'User not found.' });
        }

        const hashedPassword = user.password;

        const validPassword = await bcrypt.compare(password, hashedPassword);
        // If password is incorrect show error message
        if (!validPassword) {
            return done(null, false, { message: 'Incorrect password.' });
        }
        return done(null, user);
    } catch (error) {
        return done(error);
    }
}));

// Passport.js user serialization and deserialization (save user id in session)
passport.serializeUser((user, done) => {
    done(null, user.id);
});
passport.deserializeUser(async (id, done) => {
    try {
        const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
        const user = result.rows[0];
        return done(null, user);
    } catch (error) {
        return done(error);
    }
});

// Connect to database
connectDB();

// Start page
app.get('/', (req, res) => {
    res.render('index.ejs');
});

// Login page
app.get('/login', (req, res) => {
    res.render('login.ejs');
});

// Register page
app.get('/register', (req, res) => {
    res.render('signup.ejs');
});

// Register a new user
app.post('/register', async (req, res) => {
    let firstName = req.body.firstName;
    let lastName = req.body.lastName;
    let email = req.body.email;
    let password = req.body.password;
    let username = req.body.username;

    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        const savedUser = result.rows[0];

        if (savedUser) {
            req.flash('error', 'User already registered.');
            res.redirect('/register');
        } else {
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);
            await db.query(`INSERT INTO users (firstName, lastName, email, password, username) 
                            VALUES ($1, $2, $3, $4, $5)`, 
                            [firstName, lastName, email, hashedPassword, username]);
            
            passport.authenticate('local', {
                successRedirect: '/home',
                failureRedirect: '/login',
                failureFlash: true
            })(req, res);
        }
    } catch (error) {
        req.flash('error', error.message);
        res.redirect('/register');
    }
});

// Login a user
app.post('/login', passport.authenticate('local', {
    successRedirect: '/home',
    failureRedirect: '/login',
    failureFlash: true
}));

// Home page
app.get('/home', async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const userTodosResult = await db.query('SELECT * FROM todosHome WHERE user_id = $1', [req.user.id]);
            console.log(userTodosResult);
            const userTodos = userTodosResult.rows;
            res.render('home.ejs', { user: req.user, todos: userTodos });
        } catch (error) {
            res.render('error.ejs', { error: error.message });
        }
    } else {
        res.redirect('/login');
    }
});

// Work page
app.get('/work', async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const userTodosResult = await db.query('SELECT * FROM todoswork WHERE user_id = $1', [req.user.id]);
            const userTodos = userTodosResult.rows;
            res.render('work.ejs', { user: req.user, todos: userTodos });
        } catch (error) {
            res.render('error.ejs', { error: error.message });
        }
    } else {
        res.redirect('/login');
    }
});

// Create a new todo - home
app.post('/home/create', async (req, res) => {
    let todoText = req.body.todo;

    if (req.isAuthenticated()) {
        try {
            await db.query(`INSERT INTO todoshome (text, user_id) VALUES ($1, $2)`, [todoText, req.user.id]);
            res.redirect('/home');
        } catch (error) {
            res.render('error.ejs', { error: error.message });
        }
    } else {
        res.redirect('/login');
    }
});

// Create a new todo - work
app.post('/work/create', async (req, res) => {
    let todoText = req.body.todo;

    if (req.isAuthenticated()) {
        try {
            await db.query(`INSERT INTO todoswork (text, user_id) VALUES ($1, $2)`, [todoText, req.user.id]);
            res.redirect('/work');
        } catch (error) {
            res.render('error.ejs', { error: error.message });
        }
    } else {
        res.redirect('/login');
    }
});

// Delete a todo - home
app.post('/home/delete', async (req, res) => {
    if (req.isAuthenticated()) {
        const todoDelete = req.body.id;

        try {
            await db.query(`DELETE FROM todosHome WHERE id = $1`, [todoDelete]);
            res.redirect('/home');
        } catch (error) {
            req.flash('error', error.message);
        }
    }
});

// Delete a todo - work
app.post('/work/delete', async (req, res) => {
    if (req.isAuthenticated()) {
        const todoDelete = req.body.id;

        try {
            await db.query(`DELETE FROM todosWork WHERE id = $1`, [todoDelete]);
            res.redirect('/work');
        } catch (error) {
            req.flash('error', error.message);
        }
    }
});

// Delete all todos - home
app.post('/home/deleteAll', async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            await db.query(`DELETE FROM todosHome WHERE user_id = $1`, [req.user.id]);
            res.redirect('/home');
        } catch (error) {
            req.flash('error', error.message);
        }
    }
});

// Delete all todos - work
app.post('/work/deleteAll', async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            await db.query(`DELETE FROM todosWork WHERE user_id = $1`, [req.user.id]);
            res.redirect('/work');
        } catch (error) {
            req.flash('error', error.message);
        }
    }
});

// Logout a user
app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            return res.redirect('/');
        }
        res.redirect('/');
    });
});

// Listen to port
app.listen(port, () => {
    console.log(`Example app listening at port: ${port}`);
});

async function connectDB() {
    try {
        await db.connect();
        console.log('Connected to database');
    } catch (error) {
        console.log(error);
    }
}