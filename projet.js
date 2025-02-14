require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const passport = require("passport");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const multer = require("multer");
const cors = require("cors");
const passportJWT = require("passport-jwt");

const app = express();
const port = process.env.PORT || 4000;

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(passport.initialize());




// Connexion BDD
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});


db.connect(err => {
    if (err) {
        console.error("Connexion echouée :", err);
    } else {
        console.log("Connexion réussi");
    }
});





const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET
};

passport.use(new JwtStrategy(jwtOptions, (jwt_payload, done) => {
    db.query("SELECT id, email, role FROM users WHERE id = ?", [jwt_payload.id], (err, results) => {
        if (err) return done(err, false);
        if (results.length > 0) return done(null, results[0]);
        return done(null, false);
    });
}));



// Ca marche

app.get("/test", (req, res) => {
    res.send("hello");
});






app.post("/register", async (req, res) => {
    const { email, password } = req.body;
    
    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
        if (err) return res.status(500).json({ error: "Erreur serveur" });
        if (results.length > 0) return res.status(400).json({ error: "Email déjà utilisé" });

        const hashedPassword = await bcrypt.hash(password, 10);

        db.query("INSERT INTO users (email, password) VALUES (?, ?)", [email, hashedPassword], (err) => {
            if (err) return res.status(500).json({ error: "Erreur" });
            res.json({ message: "Utilisateur créé" });
        });
    });
});




app.post("/login", (req, res) => {
    const { email, password } = req.body;

    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
        if (err) return res.status(500).json({ error: "Erreur serveur" });
        if (results.length === 0) return res.status(401).json({ error: "Bad credentials" });

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) return res.status(401).json({ error: "Bad credentials" });

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ token });
    });
});





app.get("/profil", passport.authenticate("jwt", { session: false }), (req, res) => {
    db.query("SELECT email, role FROM users WHERE id = ?", [req.user.id], (err, results) => {
        if (err) return res.status(500).json({ error: "Erreur serveur" });
        if (results.length === 0) return res.status(404).json({ error: "Utilisateur non trouvé" });

        res.json(results[0]);
    });
});




app.get("/users/list", passport.authenticate("jwt", { session: false }), (req, res) => {
    if (req.user.role !== "admin") return res.status(403).json({ error: "Accès refusé" });

    db.query("SELECT id, email, role FROM users", (err, results) => {
        if (err) return res.status(500).json({ error: "Erreur serveur" });
        res.json(results);
    });
});







app.post("/users/ban", passport.authenticate("jwt", { session: false }), (req, res) => {
    if (req.user.role !== "admin") return res.status(403).json({ error: "Accès refusé" });

    const { email } = req.body;
    db.query("UPDATE users SET isBanned = TRUE WHERE email = ?", [email], (err) => {
        if (err) return res.status(500).json({ error: "Erreur serveur" });
        res.json({ message: "Utilisateur banni" });
    });
});





const storage = multer.diskStorage({
    destination: "uploads/",
    filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname)
});
const upload = multer({ storage });

app.post("/add-file", passport.authenticate("jwt", { session: false }), upload.single("fichier"), (req, res) => {
    res.json({ message: "Fichier uploadé", filename: req.file.filename });
});








app.post("/users/rm", passport.authenticate("jwt", { session: false }), (req, res) => {
    if (req.user.role !== "admin") return res.status(403).json({ error: "Accès refusé" });

    const { email } = req.body;
    db.query("DELETE FROM users WHERE email = ?", [email], (err) => {
        if (err) {
            console.error("Erreur SQL (DELETE) :", err);
            return res.status(500).json({ error: "Erreur lors de la suppression" });
        }
        res.json({ message: "Utilisateur supprimé avec succès" });
    });
});






app.post("/user/up", passport.authenticate("jwt", { session: false }), (req, res) => {
    if (req.user.role !== "admin") return res.status(403).json({ error: "Accès refusé" });

    const { email } = req.body;
    db.query("UPDATE users SET role = 'admin' WHERE email = ?", [email], (err) => {
        if (err) {
            console.error("Erreur SQL (UPDATE -> admin) :", err);
            return res.status(500).json({ error: "Erreur" });
        }
        res.json({ message: "Utilisateur up" });
    });
});





app.post("/user/down", passport.authenticate("jwt", { session: false }), (req, res) => {
    if (req.user.role !== "admin") return res.status(403).json({ error: "Accès refusé" });

    const { email } = req.body;
    db.query("UPDATE users SET role = 'user' WHERE email = ?", [email], (err) => {
        if (err) {
            console.error("Erreur SQL (UPDATE -> user) :", err);
            return res.status(500).json({ error: "Erreur lors de la modification" });
        }
        res.json({ message: "Administrateur down" });
    });
});




app.listen(port, () => {
    console.log(`URL Serveur : http://localhost:${port}`);
});
