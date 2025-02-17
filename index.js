import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import env from "dotenv";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60
    }
}));
app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    password: process.env.DB_PASSWORD
});

db.connect();

app.get("/", (req, res) => {
    console.log(req.user);
    res.render("index.ejs", { title: "Home", page: "home", user: req.user });
});

app.get("/shop", (req, res) => {
    if (req.isAuthenticated()) {
        return res.render("shop.ejs", { title: "Shop", page: "shop", user: req.user });
    }
    res.redirect("/login");
});

app.get("/login", (req, res) => {
    res.render("login-signup.ejs", { title: "Login", page: "login" });
});

app.get("/register", (req, res) => {
    res.render("login-signup.ejs", { title: "Sign Up", page: "register" });
});

app.post("/login", passport.authenticate("local", {
    successRedirect: "/shop",
    failureRedirect: "/login"
}));

app.post("/register", async (req, res) => {
    const email = req.body.email.length > 0 ? req.body.email : null;
    let password = null;
    try {
        password = req.body.password.length > 0 ? await bcrypt.hash(req.body.password, saltRounds) : null;
    } catch (error) {
        return res.sendStatus(500);
    }
    
    let result;
    try {
        result = await db.query("INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *;", [email, password]);
    } catch (error) {
        if (error.code === "23505") {
            return res.send("Email taken.");
        } else if (error.code === "23502") {
            return res.send("Username or password cannot be empty.");
        } else {
            return res.send("Server error. Please contact an administrator.");
        }
    }
    return res.redirect("/login");
});

passport.use(
    "local",
    new Strategy(async function verify(username, password, cb) {
        let result;
        try {
            result = await db.query("SELECT * FROM users WHERE email = $1;", [username]);
        } catch (error) {
            return cb(error);
        }
        
        if (result.rows.length === 0) {
            return cb(null, false, { message: "Invalid email or password." });
        }

        let isValid = false;
        try {
            isValid = await bcrypt.compare(password, result.rows[0].password);
        } catch (error) {
            return cb(error);
        }
        
        if (!isValid) {
            return cb(null, false, { message: "Invalid email or password." });
        }

        cb(null, result.rows[0]);
    })
);

passport.serializeUser((user, cb) => {
    cb(null, user.id);
});

passport.deserializeUser(async (user, cb) => {
    let result;
    try {
        result = await db.query("SELECT * FROM users WHERE id = $1;", [user]);
    } catch (error) {
        return cb(error);
    }
    if (result.rows.length === 0) {
        return cb(new Error("User not found."));
    }

    cb(null, result.rows[0]);
});

app.listen(port, () => {
    console.log(`Server is listening on http://localhost:${port}`);
});