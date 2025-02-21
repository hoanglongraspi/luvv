require('dotenv').config();
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const db = require('./db');
const Image = require('./imageModel');
const session = require('express-session');
const User = require('./models/User');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

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

// Configure nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

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
                error: 'Please enter both username/email and password' 
            });
        }

        // Find user by username or email (case insensitive)
        const user = await User.findOne({
            $or: [
                { username: username },
                { email: username.toLowerCase() }  // Convert email to lowercase
            ]
        });

        if (!user) {
            return res.render('login', { 
                error: 'Invalid username/email or password' 
            });
        }

        // Use the comparePassword method from the User model
        const isValidPassword = await user.comparePassword(password);
        if (!isValidPassword) {
            return res.render('login', { 
                error: 'Invalid username/email or password' 
            });
        }

        // Set session data
        req.session.userId = user._id;
        req.session.username = user.username;
        req.session.name = user.name;
        req.session.theme = theme || 'blue';
        
        return res.redirect('/');

    } catch (error) {
        console.error('Login error:', error);
        res.render('login', { 
            error: 'An error occurred during login' 
        });
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
        const { username, password, confirmPassword, name, email } = req.body;

        // Validation
        if (!email || !username || !password || !name) {
            return res.render('register', { 
                error: 'All fields are required'
            });
        }

        // Email format validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.render('register', { 
                error: 'Please enter a valid email address' 
            });
        }

        // Check for existing user
        const existingUser = await User.findOne({
            $or: [
                { email: email.toLowerCase() },
                { username: username }
            ]
        });

        if (existingUser) {
            if (existingUser.email === email.toLowerCase()) {
                return res.render('register', { error: 'Email already registered' });
            }
            if (existingUser.username === username) {
                return res.render('register', { error: 'Username already exists' });
            }
        }

        // Create new user
        const user = new User({
            name: name,
            username: username,
            email: email.toLowerCase(),
            password: password
        });

        await user.save();

        // Auto login after registration
        req.session.userId = user._id;
        req.session.name = user.name;
        res.redirect('/');

    } catch (error) {
        console.error('Registration error:', error);
        res.render('register', { 
            error: error.message || 'An error occurred during registration' 
        });
    }
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

// Forgot password routes
app.get('/forgot-password', (req, res) => {
    res.render('forgot-password', {
        error: null,
        success: null
    });
});

app.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.render('forgot-password', {
                error: 'Please enter your email address',
                success: null
            });
        }

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.render('forgot-password', {
                error: 'No account with that email address exists',
                success: null
            });
        }

        const token = crypto.randomBytes(32).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        const resetUrl = `http://${req.headers.host}/reset-password/${token}`;
        
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Password Reset Request',
            html: `
                <h2>Password Reset Request</h2>
                <p>You are receiving this because you (or someone else) requested a password reset.</p>
                <p>Please click the button below to reset your password:</p>
                <a href="${resetUrl}" style="background-color: #4CAF50; color: white; padding: 14px 20px; text-align: center; text-decoration: none; display: inline-block; border-radius: 4px;">Reset Password</a>
                <p>If you did not request this, please ignore this email.</p>
            `
        };

        await transporter.sendMail(mailOptions);
        res.render('forgot-password', {
            error: null,
            success: 'An email has been sent with further instructions.'
        });

    } catch (error) {
        console.error('Password reset error:', error);
        res.render('forgot-password', {
            error: 'An error occurred. Please try again.',
            success: null
        });
    }
});

app.get('/reset-password/:token', async (req, res) => {
    try {
        const user = await User.findOne({
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.render('reset-password', {
                error: 'Password reset token is invalid or has expired.',
                token: null
            });
        }

        res.render('reset-password', {
            error: null,
            token: req.params.token
        });
    } catch (error) {
        res.render('reset-password', {
            error: 'An error occurred',
            token: null
        });
    }
});

app.post('/reset-password/:token', async (req, res) => {
    try {
        const { password, confirmPassword } = req.body;

        if (password !== confirmPassword) {
            return res.render('reset-password', {
                error: 'Passwords do not match',
                token: req.params.token
            });
        }

        const user = await User.findOne({
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.render('reset-password', {
                error: 'Password reset token is invalid or has expired.',
                token: null
            });
        }

        user.password = password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.redirect('/login');
    } catch (error) {
        console.error('Reset password error:', error);
        res.render('reset-password', {
            error: 'An error occurred while resetting your password.',
            token: req.params.token
        });
    }
});

app.get('/', (req, res) => {
    res.render('index', {
        name: req.session.name || 'Guest'
    });
});

// Add these routes after your existing routes
app.get('/settings', requireLogin, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.redirect('/login');
        }
        
        res.render('settings', {
            user: user,
            error: null,
            success: null
        });
    } catch (error) {
        console.error('Settings error:', error);
        res.render('error', { 
            error: 'Error loading settings',
            name: req.session.name || 'Guest'
        });
    }
});

app.post('/settings', requireLogin, async (req, res) => {
    try {
        const { name, email, username, currentPassword, newPassword } = req.body;
        const user = await User.findById(req.session.userId);

        if (!user) {
            return res.redirect('/login');
        }

        // Verify current password
        const isValidPassword = await user.comparePassword(currentPassword);
        if (!isValidPassword) {
            return res.render('settings', {
                user: user,
                error: 'Current password is incorrect',
                success: null
            });
        }

        // Check if email or username already exists
        if (email !== user.email || username !== user.username) {
            const existingUser = await User.findOne({
                $or: [
                    { email: email.toLowerCase(), _id: { $ne: user._id } },
                    { username: username, _id: { $ne: user._id } }
                ]
            });

            if (existingUser) {
                if (existingUser.email === email.toLowerCase()) {
                    return res.render('settings', {
                        user: user,
                        error: 'Email already in use',
                        success: null
                    });
                }
                if (existingUser.username === username) {
                    return res.render('settings', {
                        user: user,
                        error: 'Username already taken',
                        success: null
                    });
                }
            }
        }

        // Update user information
        user.name = name;
        user.email = email.toLowerCase();
        user.username = username;

        // Update password if provided
        if (newPassword) {
            user.password = newPassword;
        }

        await user.save();

        // Update session
        req.session.name = user.name;

        res.render('settings', {
            user: user,
            error: null,
            success: 'Settings updated successfully'
        });

    } catch (error) {
        console.error('Settings update error:', error);
        res.render('settings', {
            user: req.user,
            error: 'An error occurred while updating settings',
            success: null
        });
    }
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

// Move the 404 handler to the end
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

module.exports = app;