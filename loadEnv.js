const fs = require('fs');
const os = require('os');
const path = require('path');
const dotenv = require('dotenv');

function loadEnv() {
  const candidates = [
    process.env.HIRFATI_ENV_FILE,
    path.join(os.homedir(), '.hirfati', 'backend.env'),
    path.join(__dirname, '.env')
  ].filter(Boolean);

  for (const envPath of candidates) {
    if (fs.existsSync(envPath)) {
      dotenv.config({ path: envPath, override: false, quiet: true });
    }
  }
}

module.exports = loadEnv;
