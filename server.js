/* 
   server.js - The Backend 
   Run this using command: node server.js 
*/

const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const app = express();
const PORT = 3000;

// Ensure uploads directory exists
const uploadDir = './public/uploads';
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Storage Configuration
const storage = multer.diskStorage({
    destination: uploadDir,
    filename: function(req, file, cb) {
        // Clean the filename and add timestamp to prevent overwriting
        // Example: mypage.html -> mypage-163402030.html
        const name = path.parse(file.originalname).name.replace(/\s+/g, '-').toLowerCase();
        const ext = path.parse(file.originalname).ext;
        cb(null, `${name}-${Date.now()}${ext}`);
    }
});

const upload = multer({ storage: storage });

// Serve static files (HTML, CSS, JS) from 'public' folder
app.use(express.static('public'));

// Upload Endpoint
app.post('/upload', upload.single('htmlFile'), (req, res) => {
    if (!req.file) return res.status(400).json({ success: false, error: 'No file uploaded' });

    // Construct the URL
    const protocol = req.protocol;
    const host = req.get('host');
    // Result: http://localhost:3000/uploads/filename.html
    const fileUrl = `${protocol}://${host}/uploads/${req.file.filename}`;

    res.json({ success: true, url: fileUrl });
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
