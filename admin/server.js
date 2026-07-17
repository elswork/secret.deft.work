const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || '/app/data';
const SECRETS_DIR = path.join(DATA_DIR, 'secrets');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const COOKIE_NAME = 'secret_admin_session';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Simple Auth Middleware
function requireAuth(req, res, next) {
  const cookieHeader = req.headers.cookie || '';
  const cookies = Object.fromEntries(cookieHeader.split('; ').map(c => {
    const parts = c.split('=');
    return [parts[0], parts.slice(1).join('=')];
  }));
  
  if (cookies[COOKIE_NAME] === ADMIN_PASSWORD) {
    next();
  } else {
    if (req.path.startsWith('/api/')) {
      res.status(401).json({ error: 'Unauthorized' });
    } else {
      res.redirect('/login');
    }
  }
}

// Serve Views
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.post('/login', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    // Set cookie valid for 24 hours
    res.setHeader('Set-Cookie', `${COOKIE_NAME}=${password}; Path=/; HttpOnly; Max-Age=86400`);
    res.redirect('/');
  } else {
    res.redirect('/login?error=1');
  }
});

app.get('/logout', (req, res) => {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Path=/; HttpOnly; Max-Age=0`);
  res.redirect('/login');
});

app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

// API: List all secrets (metadata only)
app.get('/api/secrets', requireAuth, (req, res) => {
  if (!fs.existsSync(SECRETS_DIR)) {
    return res.json([]);
  }
  
  try {
    const files = fs.readdirSync(SECRETS_DIR);
    const secrets = [];
    
    files.forEach(file => {
      if (file.endsWith('.json')) {
        const filePath = path.join(SECRETS_DIR, file);
        try {
          const content = fs.readFileSync(filePath, 'utf8');
          const data = JSON.parse(content);
          
          secrets.push({
            id: data.id,
            createdAt: data.createdAt,
            releaseDate: data.releaseDate,
            expireDate: data.expireDate,
            oneTime: data.oneTime,
            size: content.length
          });
        } catch (e) {
          // Skip corrupt or locked files
        }
      }
    });
    
    // Sort by creation date descending
    secrets.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json(secrets);
  } catch (err) {
    console.error('Error listing secrets:', err);
    res.status(500).json({ error: 'Failed to read secrets directory' });
  }
});

// API: Get single secret metadata & encrypted content
app.get('/api/secrets/:id', requireAuth, (req, res) => {
  const id = req.params.id;
  if (!/^[0-9a-f]{24}$/.test(id)) {
    return res.status(400).json({ error: 'Invalid secret ID format.' });
  }
  
  const filePath = path.join(SECRETS_DIR, `${id}.json`);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'Secret not found.' });
  }
  
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const data = JSON.parse(content);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to read secret content.' });
  }
});

// API: Delete a secret manually
app.delete('/api/secrets/:id', requireAuth, (req, res) => {
  const id = req.params.id;
  if (!/^[0-9a-f]{24}$/.test(id)) {
    return res.status(400).json({ error: 'Invalid ID format' });
  }
  
  const filePath = path.join(SECRETS_DIR, `${id}.json`);
  if (fs.existsSync(filePath)) {
    try {
      fs.unlinkSync(filePath);
      res.json({ success: true });
    } catch (err) {
      console.error('Error deleting secret:', err);
      res.status(500).json({ error: 'Failed to delete secret file' });
    }
  } else {
    res.status(404).json({ error: 'Secret not found' });
  }
});

app.listen(PORT, () => {
  console.log(`Admin server running on port ${PORT}`);
});
