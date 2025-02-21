const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const db = require('./db');
const Image = require('./imageModel');
const session = require('express-session');
const User = require('./models/User');
const bcrypt = require('bcrypt');

const app = express();
app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Method override middleware
const methodOverride = require('method-override');
app.use(methodOverride('_method'));

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)){
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure multer for memory storage instead of disk
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Add session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'default_secret',
    resave: false,
    saveUninitialized: true
}));

// Authentication middleware
const requireLogin = async (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    try {
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.redirect('/login');
        }
        next();
    } catch (error) {
        console.error('Auth error:', error);
        res.redirect('/login');
    }
};

// Login routes
app.get('/login', (req, res) => {
    // If user is already logged in, redirect to home
    if (req.session.userId) {
        return res.redirect('/');
    }
    res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
    try {
        const { username, password, theme } = req.body;

        // Basic validation
        if (!username || !password) {
            return res.render('login', { 
                error: 'Please enter both username and password' 
            });
        }

        // Find user by username
        const user = await User.findOne({ username });
        if (!user) {
            return res.render('login', { error: 'Invalid username or password' });
        }

        // Compare password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.render('login', { error: 'Invalid username or password' });
        }

        // Set session data
        req.session.userId = user._id;
        req.session.username = user.username;
        req.session.name = user.name;
        req.session.theme = theme || 'blue';
        
        return res.redirect('/');

    } catch (error) {
        console.error('Login error:', error);
        res.render('login', { error: 'An error occurred during login' });
    }
});

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Protect your gallery routes
app.get('/', requireLogin, async (req, res) => {
    try {
        const images = await Image.find().sort({ createdAt: -1 });
        const user = await User.findById(req.session.userId);
        
        if (!user) {
            return res.redirect('/login');
        }

        res.render('index', {
            images: images || [],
            user: user,
            theme: req.session.theme || 'blue'
        });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).render('error', { 
            error: 'Error loading gallery',
            user: { name: 'Guest' }
        });
    }
});

app.post('/upload', upload.single('image'), async (req, res) => {
    try {
        const image = new Image({
            img: {
                data: req.file.buffer,
                contentType: req.file.mimetype
            }
        });
        await image.save();
        res.redirect('/');
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).send('Error uploading file');
    }
});

app.delete('/images/:id', async (req, res) => {
    try {
        const result = await Image.findByIdAndDelete(req.params.id);
        if (!result) {
            return res.status(404).json({ error: 'Image not found' });
        }
        res.json({ success: true, message: 'Image deleted successfully' });
    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).json({ error: 'Failed to delete image' });
    }
});

// Registration routes
app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    try {
        const { username, password, confirmPassword, name } = req.body;

        // Validation
        if (password !== confirmPassword) {
            return res.render('register', { error: 'Passwords do not match' });
        }

        if (password.length < 6) {
            return res.render('register', { error: 'Password must be at least 6 characters long' });
        }

        if (username.length < 3) {
            return res.render('register', { error: 'Username must be at least 3 characters long' });
        }

        // Check if username already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.render('register', { error: 'Username already exists' });
        }

        // Create new user without email field
        const user = new User({
            name,
            username,
            password
        });

        await user.save();

        // Auto login after registration
        req.session.userId = user._id;
        req.session.name = user.name;
        res.redirect('/');

    } catch (error) {
        console.error('Registration error:', error);
        res.render('register', { error: 'An error occurred during registration' });
    }
});

app.get('/', (req, res) => {
    res.render('index', {
        name: req.session.name || 'Guest'
    });
});

app.use((req, res) => {
    res.status(404).render('error', { 
        error: 'Page not found',
        name: req.session.name || 'Guest'
    });
});

app.get('/images/:id', requireLogin, async (req, res) => {
    try {
        const image = await Image.findById(req.params.id);
        if (!image) {
            return res.status(404).render('error', { 
                error: 'Image not found',
                name: req.session.name || 'Guest'
            });
        }
        res.render('image', {
            image: image,
            name: req.session.name || 'Guest'
        });
    } catch (error) {
        console.error('Error:', error);
        res.render('error', { 
            error: 'Error loading image',
            name: req.session.name || 'Guest'
        });
    }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

// Error handler middleware
app.use((err, req, res, next) => {
    console.error(err);
    if (err.name === 'ReferenceError') {
        return res.redirect('/login');
    }
    res.status(err.status || 500).render('error', {
        error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message,
        name: req.session.name || 'Guest'
    });
});

// Add this route to handle theme updates
app.post('/update-theme', (req, res) => {
    const { theme } = req.body;
    if (theme) {
        req.session.theme = theme;
        res.json({ success: true });
    } else {
        res.status(400).json({ success: false, error: 'Theme not provided' });
    }
});

module.exports = app;