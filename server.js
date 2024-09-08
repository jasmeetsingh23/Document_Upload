import express from 'express';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import cloudinary from 'cloudinary';
import { v2 as cloudinaryV2 } from 'cloudinary';
import dotenv from 'dotenv';
import cors from 'cors';
import colors from 'colors';
import { fileURLToPath } from 'url';  
import { dirname } from 'path'; 

dotenv.config();

const app = express();
app.use(cors());
const PORT = process.env.PORT || 8080;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Define __filename and __dirname for ES module
const __filename = fileURLToPath(import.meta.url);  
const __dirname = dirname(__filename);  

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB connected'.bgMagenta.white))
  .catch((err) => console.error(err));

// Cloudinary Configuration
cloudinaryV2.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Models
const userSchema = new mongoose.Schema({
  name: String,
  employeeID: { type: String, unique: true },
  department: { type: String, enum: ['Admin', "HR", "Sales", "Finance", "Marketing", "BPO", 'dept6'] },
  designation: { type: String, enum: ['Supervisor', 'Worker'] },
  password: String,
  shift: { type: String, enum: ['A', 'B'] },
});

const User = mongoose.model('User', userSchema);

const documentSchema = new mongoose.Schema({
  filename: String,
  fileVersion: String,
  category: { type: String, enum: ['Policies', 'Forms Format', 'SOP', 'Work Instructions'] },
  status: { type: String, enum: ['Pending', 'Approved', 'Rejected'], default: 'Pending' },
  cloudinaryId: String,
  fileUrl: String,
  department: String,
  designation: String,
  shift: String
}, { timestamps: true });

const Document = mongoose.model('Document', documentSchema);

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Multer Setup
const storage = multer.memoryStorage(); // Store file in memory
const upload = multer({ storage: storage });

// Routes
app.post('/signup', async (req, res) => {
  try {
    const { name, employeeID, department, designation, password, shift } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, employeeID, department, designation, password: hashedPassword, shift });
    await newUser.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/login', async (req, res) => {
  const { employeeID, password } = req.body;
  const user = await User.findOne({ employeeID });
  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ employeeID: user.employeeID }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, name: user.name, department: user.department, designation: user.designation, shift: user.shift });
  } else {
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

app.post('/upload', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    const { file } = req;
    const { fileVersion, status, category } = req.body;

    if (!file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    // Find the user based on the employeeID stored in the JWT token
    const user = await User.findOne({ employeeID: req.user.employeeID });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Upload file to Cloudinary
    cloudinaryV2.uploader.upload_stream(
      { resource_type: 'auto' },
      async (error, result) => {
        if (error) {
          return res.status(500).json({ error: error.message });
        }

        const newDocument = new Document({
          filename: result.original_filename,
          fileVersion,
          category,
          status,
          cloudinaryId: result.public_id,
          fileUrl: result.secure_url,
          department: user.department,
          designation: user.designation,
          shift: user.shift
        });

        await newDocument.save();

        res.json({
          documentId: newDocument._id,
          fileUrl: newDocument.fileUrl,
          department: newDocument.department,
          designation: newDocument.designation,
          shift: newDocument.shift
        });
      }
    ).end(file.buffer);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/documents', async (req, res) => {
  try {
    const documents = await Document.find();
    res.json(documents);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/recent-files', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    const recentFiles = await Document.find()
      .sort({ createdAt: -1 })
      .limit(limit);
    res.json(recentFiles);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/documents/:id', async (req, res) => {
  try {
    const document = await Document.findById(req.params.id);
    if (document) {
      await cloudinaryV2.uploader.destroy(document.cloudinaryId);
      await Document.findByIdAndDelete(req.params.id);
      res.json({ message: 'Document deleted' });
    } else {
      res.status(404).json({ message: 'Document not found' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/documents/:id', async (req, res) => {
  try {
    const { filename, fileVersion, category, status } = req.body;
    const updatedDocument = await Document.findByIdAndUpdate(req.params.id, 
      { filename, fileVersion, category, status }, 
      { new: true }
    );
    res.json(updatedDocument);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`.bgCyan.white));
