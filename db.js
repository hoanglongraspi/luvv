const mongoose = require('mongoose');

const mongoURI = "mongodb+srv://mindbox:Mindbox123%40@cluster0.oh89z.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
if (!mongoURI) {
    throw new Error('MONGODB_URI is not defined');
}

mongoose.connect(mongoURI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

module.exports = mongoose;