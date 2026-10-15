// AITHENA live telemetry — authentication helpers (0 dependencies)
// Admin token + per-device agent secrets. Constant-time comparison.
'use strict';

const crypto = require('crypto');

// Generate a URL-safe random token (hex).
function newToken(bytes) {
  return crypto.randomBytes(bytes || 32).toString('hex');
}

// Generate a device-scoped agent secret. Prefixed so logs/leaks are recognisable
// and never collide with the admin token namespace.
function newAgentSecret() {
  return 'agt_' + newToken(32);
}

// Constant-time string compare that never throws on length mismatch.
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) {
    // Still do a comparison to keep timing roughly flat, but result is false.
    crypto.timingSafeEqual(ab, ab);
    return false;
  }
  return crypto.timingSafeEqual(ab, bb);
}

// Extract a Bearer token from an Authorization header value.
function bearer(header) {
  if (!header || typeof header !== 'string') return null;
  const m = header.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

// Store a secret only as a salted hash so a leaked registry file does not leak
// usable agent credentials.
function hashSecret(secret) {
  const salt = crypto.randomBytes(16).toString('hex');
  const h = crypto.createHash('sha256').update(salt + ':' + secret).digest('hex');
  return salt + '$' + h;
}

function verifySecret(secret, stored) {
  if (!stored || typeof stored !== 'string' || stored.indexOf('$') < 0) return false;
  const [salt, h] = stored.split('$');
  const calc = crypto.createHash('sha256').update(salt + ':' + secret).digest('hex');
  return safeEqual(calc, h);
}

module.exports = { newToken, newAgentSecret, safeEqual, bearer, hashSecret, verifySecret };
