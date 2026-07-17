// Helper functions for Hex <-> Buffer conversion
function bufToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBuf(hex) {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes.buffer;
}

// Zero-knowledge Encryption client-side
async function encryptText(plaintext, password) {
  const encoder = new TextEncoder();
  const plainBytes = encoder.encode(plaintext);

  // Generate 16 bytes random salt
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  
  // Import the password as a PBKDF2 base key
  const baseKey = await window.crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  // Derive the 256-bit AES-GCM key using PBKDF2 with 100,000 iterations
  const key = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );

  // Generate 12 bytes random IV (Initialization Vector)
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  // Encrypt the payload
  const encrypted = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    key,
    plainBytes
  );

  return {
    encryptedText: bufToHex(encrypted),
    iv: bufToHex(iv),
    salt: bufToHex(salt)
  };
}

// Zero-knowledge Decryption client-side
async function decryptText(encryptedHex, ivHex, saltHex, password) {
  const decoder = new TextDecoder();
  const ciphertext = hexToBuf(encryptedHex);
  const iv = hexToBuf(ivHex);
  const salt = hexToBuf(saltHex);

  const encoder = new TextEncoder();
  const baseKey = await window.crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  const key = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    key,
    ciphertext
  );

  return decoder.decode(decrypted);
}

// Global state
let currentSecretPayload = null;
let currentCountdownInterval = null;

// DOM Elements
const viewCreate = document.getElementById('view-create');
const viewSuccess = document.getElementById('view-success');
const viewDecrypt = document.getElementById('view-decrypt');
const viewError = document.getElementById('view-error');

const createForm = document.getElementById('create-form');
const secretText = document.getElementById('secretText');
const charCounter = document.getElementById('char-counter');
const secretPassword = document.getElementById('secretPassword');
const genPasswordBtn = document.getElementById('genPasswordBtn');
const strengthContainer = document.getElementById('strength-container');
const strengthBar = document.getElementById('strength-bar');
const strengthText = document.getElementById('strength-text');
const releaseDate = document.getElementById('releaseDate');
const expireDate = document.getElementById('expireDate');
const oneTime = document.getElementById('oneTime');
const submitBtn = document.getElementById('submitBtn');
const createSpinner = document.getElementById('create-spinner');

const shareLinkInput = document.getElementById('shareLinkInput');
const copyLinkBtn = document.getElementById('copyLinkBtn');
const noticeOnetimer = document.getElementById('notice-onetimer');
const resetBtn = document.getElementById('resetBtn');
const logoLink = document.getElementById('logo-link');

const decryptForm = document.getElementById('decrypt-form');
const decryptPassword = document.getElementById('decryptPassword');
const decryptBtn = document.getElementById('decryptBtn');
const decryptSpinner = document.getElementById('decrypt-spinner');
const decryptedResult = document.getElementById('decrypted-result');
const decryptedText = document.getElementById('decryptedText');
const copyDecryptedBtn = document.getElementById('copyDecryptedBtn');
const downloadDecryptedBtn = document.getElementById('downloadDecryptedBtn');
const burnWarning = document.getElementById('burn-warning');
const decryptMetaInfo = document.getElementById('decrypt-meta-info');

const errorTitle = document.getElementById('error-title');
const errorMessage = document.getElementById('error-message');
const countdownWrapper = document.getElementById('countdown-wrapper');
const countdownTimer = document.getElementById('countdown-timer');

// Toggle Password Visibility
function setupPasswordToggle(inputId, toggleId) {
  const input = document.getElementById(inputId);
  const toggle = document.getElementById(toggleId);
  toggle.addEventListener('click', () => {
    if (input.type === 'password') {
      input.type = 'text';
      toggle.textContent = '🙈';
    } else {
      input.type = 'password';
      toggle.textContent = '👁️';
    }
  });
}
setupPasswordToggle('secretPassword', 'toggle-create-password');
setupPasswordToggle('decryptPassword', 'toggle-decrypt-password');

// Accordion Logic
const optionsTrigger = document.getElementById('options-trigger');
const optionsContent = document.getElementById('options-content');
optionsTrigger.addEventListener('click', () => {
  optionsTrigger.classList.toggle('active');
  optionsContent.classList.toggle('open');
});

// Byte/Char Counter logic (up to 1KB bytes)
secretText.addEventListener('input', () => {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(secretText.value).length;
  charCounter.textContent = `${bytes} / 1024 bytes`;
  if (bytes > 1024) {
    charCounter.style.color = 'var(--text-error)';
  } else {
    charCounter.style.color = 'var(--text-muted)';
  }
});

// Switch views utility
function showView(view) {
  [viewCreate, viewSuccess, viewDecrypt, viewError].forEach(v => v.classList.add('hidden'));
  view.classList.remove('hidden');
}

// Copy to Clipboard Helpers
async function copyToClipboard(inputEl, buttonEl, successText) {
  try {
    await navigator.clipboard.writeText(inputEl.value || inputEl.dataset.raw || inputEl.textContent);
    const originalText = buttonEl.textContent;
    buttonEl.textContent = successText;
    buttonEl.style.borderColor = 'var(--text-success)';
    buttonEl.style.color = 'var(--text-success)';
    setTimeout(() => {
      buttonEl.textContent = originalText;
      buttonEl.style.borderColor = '';
      buttonEl.style.color = '';
    }, 2000);
  } catch (err) {
    alert('No se pudo copiar al portapapeles.');
  }
}

copyLinkBtn.addEventListener('click', () => {
  copyToClipboard(shareLinkInput, copyLinkBtn, '¡Copiado!');
});

copyDecryptedBtn.addEventListener('click', () => {
  copyToClipboard(decryptedText, copyDecryptedBtn, '✅ Copiado');
});

// Download Decrypted Secret as Markdown file
downloadDecryptedBtn.addEventListener('click', () => {
  const text = decryptedText.dataset.raw || decryptedText.textContent;
  const blob = new Blob([text], { type: 'text/markdown;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `secreto_${new Date().toISOString().slice(0, 10)}.md`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  
  // Show copy-like checkmark feedback
  const originalText = downloadDecryptedBtn.textContent;
  downloadDecryptedBtn.textContent = '✅';
  setTimeout(() => {
    downloadDecryptedBtn.textContent = originalText;
  }, 2000);
});

// Password Strength Meter evaluation
secretPassword.addEventListener('input', () => {
  const pass = secretPassword.value;
  if (!pass) {
    strengthContainer.style.display = 'none';
    strengthText.style.display = 'none';
    return;
  }
  
  strengthContainer.style.display = 'block';
  strengthText.style.display = 'block';
  
  let score = 0;
  if (pass.length >= 8) score++;
  if (pass.length >= 12) score++;
  if (/[A-Z]/.test(pass)) score++;
  if (/[0-9]/.test(pass)) score++;
  if (/[^A-Za-z0-9]/.test(pass)) score++;
  
  let width = '0%';
  let color = '';
  let text = '';
  
  if (score <= 1) {
    width = '25%';
    color = '#f87171';
    text = 'Debilidad extrema 🔴';
  } else if (score === 2 || score === 3) {
    width = '60%';
    color = '#fbbf24';
    text = 'Fortaleza media 🟡';
  } else {
    width = '100%';
    color = '#34d399';
    text = 'Seguridad impenetrable 🟢';
  }
  
  strengthBar.style.width = width;
  strengthBar.style.backgroundColor = color;
  strengthText.textContent = text;
  strengthText.style.color = color;
});

// Generate Secure Random Password
function generateSecurePassword() {
  // Exclude easily confused characters like l, 1, o, O, 0
  const chars = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*()_+-=[]{}|;:,.<>?';
  const length = 16;
  let password = '';
  const array = new Uint32Array(length);
  window.crypto.getRandomValues(array);
  for (let i = 0; i < length; i++) {
    password += chars[array[i] % chars.length];
  }
  return password;
}

genPasswordBtn.addEventListener('click', () => {
  const pass = generateSecurePassword();
  secretPassword.value = pass;
  secretPassword.dispatchEvent(new Event('input')); // Trigger strength evaluation
  
  // Show password automatically
  secretPassword.type = 'text';
  const toggle = document.getElementById('toggle-create-password');
  if (toggle) toggle.textContent = '🙈';
});

function resetToHome() {
  createForm.reset();
  charCounter.textContent = '0 / 1024 bytes';
  charCounter.style.color = 'var(--text-muted)';
  
  // Hide strength meter
  strengthContainer.style.display = 'none';
  strengthText.style.display = 'none';
  
  // Reset decrypt view states in case they are open
  decryptedResult.classList.add('hidden');
  decryptForm.classList.remove('hidden');
  decryptMetaInfo.classList.add('hidden');
  const instructions = document.getElementById('decrypt-instructions');
  if (instructions) instructions.classList.remove('hidden');
  decryptPassword.value = '';
  
  window.history.pushState({}, '', '/');
  showView(viewCreate);
}

resetBtn.addEventListener('click', resetToHome);
logoLink.addEventListener('click', (e) => {
  e.preventDefault();
  resetToHome();
});

// SUBMIT CREATE SECRET
createForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const text = secretText.value;
  const password = secretPassword.value;
  
  const encoder = new TextEncoder();
  const bytes = encoder.encode(text).length;
  
  if (bytes > 1024) {
    alert('El tamaño del mensaje excede el límite de 1KB (1024 bytes).');
    return;
  }
  
  // Date validations
  let releaseVal = releaseDate.value ? new Date(releaseDate.value).toISOString() : null;
  let expireVal = expireDate.value ? new Date(expireDate.value).toISOString() : null;
  
  const now = new Date();
  if (expireVal && new Date(expireVal) <= now) {
    alert('La fecha de expiración debe ser en el futuro.');
    return;
  }
  if (releaseVal && expireVal && new Date(releaseVal) >= new Date(expireVal)) {
    alert('La fecha de disponibilidad debe ser anterior a la de expiración.');
    return;
  }

  // Disable button, show loading
  submitBtn.disabled = true;
  createSpinner.style.display = 'block';

  try {
    // Encrypt client-side
    const encryptedData = await encryptText(text, password);
    
    // Post to API
    const response = await fetch('/api/secret', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        ...encryptedData,
        releaseDate: releaseVal,
        expireDate: expireVal,
        oneTime: oneTime.checked
      })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Error al guardar el secreto.');
    }

    // Success
    const shareUrl = `${window.location.origin}/v/${data.id}`;
    shareLinkInput.value = shareUrl;

    if (oneTime.checked) {
      noticeOnetimer.classList.remove('hidden');
    } else {
      noticeOnetimer.classList.add('hidden');
    }

    showView(viewSuccess);
  } catch (err) {
    alert(`Error: ${err.message}`);
  } finally {
    submitBtn.disabled = false;
    createSpinner.style.display = 'none';
  }
});

// Countdown timer handler for locked secrets
function startCountdown(releaseTimeStr) {
  if (currentCountdownInterval) clearInterval(currentCountdownInterval);
  countdownWrapper.classList.remove('hidden');
  
  const releaseTime = new Date(releaseTimeStr).getTime();
  
  function updateTimer() {
    const now = new Date().getTime();
    const diff = releaseTime - now;
    
    if (diff <= 0) {
      clearInterval(currentCountdownInterval);
      countdownWrapper.classList.add('hidden');
      errorTitle.textContent = 'Mensaje ya disponible';
      errorMessage.textContent = 'Recarga la página para descifrar el mensaje.';
      return;
    }
    
    const hours = Math.floor(diff / 3600000);
    const minutes = Math.floor((diff % 3600000) / 60000);
    const seconds = Math.floor((diff % 60000) / 1000);
    
    countdownTimer.textContent = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
  }
  
  updateTimer();
  currentCountdownInterval = setInterval(updateTimer, 1000);
}

// Fetch Secret from Server on load if route matches /v/<id>
async function loadSecret(id) {
  try {
    const response = await fetch(`/api/secret/${id}`);
    const data = await response.json();
    
    if (response.status === 403) {
      // Locked till release date
      errorTitle.textContent = 'Secreto Bloqueado Temporalmente';
      errorMessage.textContent = `Este mensaje estará protegido y no podrá visualizarse hasta: ${new Date(data.releaseDate).toLocaleString()}`;
      startCountdown(data.releaseDate);
      showView(viewError);
      return;
    }
    
    if (!response.ok) {
      // Expired or not found
      errorTitle.textContent = 'Secreto No Disponible';
      errorMessage.textContent = data.error || 'El secreto solicitado ha expirado o ya ha sido destruido.';
      countdownWrapper.classList.add('hidden');
      showView(viewError);
      return;
    }
    
    // Valid secret payload loaded
    currentSecretPayload = data;
    
    if (data.oneTime) {
      decryptMetaInfo.innerHTML = '🔥 <strong>Mensaje de un solo uso:</strong> Al descifrarlo se borrará permanentemente del servidor.';
      decryptMetaInfo.classList.remove('hidden');
    } else {
      decryptMetaInfo.classList.add('hidden');
    }
    
    showView(viewDecrypt);
  } catch (err) {
    errorTitle.textContent = 'Error de Conexión';
    errorMessage.textContent = 'No se pudo conectar con el servidor. Inténtalo más tarde.';
    showView(viewError);
  }
}

// SUBMIT DECRYPT SECRET
decryptForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!currentSecretPayload) return;

  const password = decryptPassword.value;
  decryptBtn.disabled = true;
  decryptSpinner.style.display = 'block';

  try {
    const decrypted = await decryptText(
      currentSecretPayload.encryptedText,
      currentSecretPayload.iv,
      currentSecretPayload.salt,
      password
    );

    // Decryption Success!
    // Parse Markdown to HTML and sanitize it using DOMPurify
    const cleanHtml = DOMPurify.sanitize(marked.parse(decrypted));
    decryptedText.innerHTML = cleanHtml;
    decryptedText.dataset.raw = decrypted; // Save raw markdown for copying
    decryptedResult.classList.remove('hidden');
    
    if (currentSecretPayload.oneTime) {
      burnWarning.classList.remove('hidden');
    } else {
      burnWarning.classList.add('hidden');
    }
    
    // Hide input form since it's already decrypted
    decryptForm.classList.add('hidden');
    decryptMetaInfo.classList.add('hidden');
    document.getElementById('decrypt-instructions').classList.add('hidden');

  } catch (err) {
    alert('Contraseña incorrecta o error al descifrar.');
  } finally {
    decryptBtn.disabled = false;
    decryptSpinner.style.display = 'none';
  }
});

// Initialize Routing
window.addEventListener('DOMContentLoaded', () => {
  const path = window.location.pathname;
  const match = path.match(/^\/v\/([0-9a-f]{24})$/);
  
  if (match) {
    const secretId = match[1];
    loadSecret(secretId);
  } else {
    showView(viewCreate);
  }
  
  // Theme Toggle Logic
  const themeToggle = document.getElementById('theme-toggle');

  function setTheme(theme) {
    if (theme === 'light') {
      document.body.classList.add('light-theme');
      if (themeToggle) themeToggle.textContent = '☀️';
      localStorage.setItem('theme', 'light');
    } else {
      document.body.classList.remove('light-theme');
      if (themeToggle) themeToggle.textContent = '🌙';
      localStorage.setItem('theme', 'dark');
    }
  }

  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      if (document.body.classList.contains('light-theme')) {
        setTheme('dark');
      } else {
        setTheme('light');
      }
    });
  }

  // Initial theme check (always default to dark mode unless explicitly set to light)
  const savedTheme = localStorage.getItem('theme');
  if (savedTheme === 'light') {
    setTheme('light');
  } else {
    setTheme('dark');
  }
});
