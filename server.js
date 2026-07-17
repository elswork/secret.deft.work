const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const SECRETS_DIR = path.join(DATA_DIR, 'secrets');

// Ensure directories exist
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
if (!fs.existsSync(SECRETS_DIR)) {
  fs.mkdirSync(SECRETS_DIR, { recursive: true });
}

app.use(cors());
app.use(express.json());

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'frontend')));

// Helper to validate and clean up file path
function getSecretPath(id) {
  // Strict regex: exactly 24 hex characters
  if (!/^[0-9a-f]{24}$/.test(id)) {
    return null;
  }
  return path.join(SECRETS_DIR, `${id}.json`);
}

// POST /api/secret - Create a new secret
app.post('/api/secret', (req, res) => {
  const { encryptedText, iv, salt, releaseDate, expireDate, oneTime } = req.body;

  // Strict validation
  if (!encryptedText || typeof encryptedText !== 'string' || encryptedText.length > 4000) {
    return res.status(400).json({ error: 'Text encrypted payload is missing, invalid or too long (max 1KB plaintext equivalent).' });
  }
  if (!iv || typeof iv !== 'string' || iv.length !== 24) {
    return res.status(400).json({ error: 'Invalid or missing Initialization Vector (IV).' });
  }
  if (!salt || typeof salt !== 'string' || salt.length !== 32) {
    return res.status(400).json({ error: 'Invalid or missing key derivation salt.' });
  }

  // Optional dates validation
  let parsedReleaseDate = null;
  if (releaseDate) {
    parsedReleaseDate = new Date(releaseDate);
    if (isNaN(parsedReleaseDate.getTime())) {
      return res.status(400).json({ error: 'Invalid release date format.' });
    }
  }

  let parsedExpireDate = null;
  if (expireDate) {
    parsedExpireDate = new Date(expireDate);
    if (isNaN(parsedExpireDate.getTime())) {
      return res.status(400).json({ error: 'Invalid expiration date format.' });
    }
  }

  // Create secret metadata object
  const secretId = crypto.randomBytes(12).toString('hex'); // 24 hex chars
  const secretData = {
    id: secretId,
    encryptedText,
    iv,
    salt,
    releaseDate: parsedReleaseDate ? parsedReleaseDate.toISOString() : null,
    expireDate: parsedExpireDate ? parsedExpireDate.toISOString() : null,
    oneTime: !!oneTime,
    createdAt: new Date().toISOString()
  };

  const secretPath = path.join(SECRETS_DIR, `${secretId}.json`);

  try {
    fs.writeFileSync(secretPath, JSON.stringify(secretData, null, 2), 'utf8');
    res.status(201).json({ id: secretId });
  } catch (err) {
    console.error('Error writing secret:', err);
    res.status(500).json({ error: 'Failed to store secret on the server.' });
  }
});

// GET /api/secret/:id - Retrieve a secret
app.get('/api/secret/:id', (req, res) => {
  const secretPath = getSecretPath(req.params.id);

  if (!secretPath) {
    return res.status(400).json({ error: 'Invalid secret ID format.' });
  }

  if (!fs.existsSync(secretPath)) {
    return res.status(404).json({ error: 'Secret not found. It may have expired or been burned (one-time use).' });
  }

  try {
    const rawData = fs.readFileSync(secretPath, 'utf8');
    const secret = JSON.parse(rawData);
    const now = new Date();

    // Check expiration date
    if (secret.expireDate && now > new Date(secret.expireDate)) {
      // Clean up expired secret
      fs.unlinkSync(secretPath);
      return res.status(410).json({ error: 'Secret has expired.' });
    }

    // Check release date (not yet viewable)
    if (secret.releaseDate && now < new Date(secret.releaseDate)) {
      return res.status(403).json({
        error: 'This secret is locked and cannot be viewed yet.',
        releaseDate: secret.releaseDate
      });
    }

    // If one-time use, delete immediately
    if (secret.oneTime) {
      fs.unlinkSync(secretPath);
    }

    // Return the encrypted content
    res.json({
      encryptedText: secret.encryptedText,
      iv: secret.iv,
      salt: secret.salt,
      oneTime: secret.oneTime
    });

  } catch (err) {
    console.error('Error retrieving secret:', err);
    res.status(500).json({ error: 'Internal server error while retrieving the secret.' });
  }
});

// Serve frontend routing fallback (routes starting with /v/ should return index.html)
app.get('/v/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

// Passive cleanup job: deletes expired files hourly
setInterval(() => {
  console.log('Running periodic cleanup of expired secrets...');
  fs.readdir(SECRETS_DIR, (err, files) => {
    if (err) {
      return console.error('Error scanning secrets directory for cleanup:', err);
    }
    const now = new Date();
    files.forEach(file => {
      if (!file.endsWith('.json')) return;
      const filePath = path.join(SECRETS_DIR, file);
      try {
        const rawData = fs.readFileSync(filePath, 'utf8');
        const secret = JSON.parse(rawData);
        if (secret.expireDate && now > new Date(secret.expireDate)) {
          fs.unlinkSync(filePath);
          console.log(`Cleaned up expired secret file: ${file}`);
        }
      } catch (e) {
        console.error(`Error checking file ${file} during cleanup:`, e);
      }
    });
  });
}, 3600000); // 1 hour

app.listen(PORT, () => {
  console.log(`Secret sharing server running on port ${PORT}`);
});
