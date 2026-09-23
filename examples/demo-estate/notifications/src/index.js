const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const express = require('express');

const app = express();

function sealMessage(key, message) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  return Buffer.concat([cipher.update(message), cipher.final()]);
}

app.post('/v1/notify', (req, res) => {
  const session = jwt.sign({ user: req.body.user }, process.env.SESSION_SECRET, { algorithm: 'HS256' });
  res.json({ session, sealed: sealMessage(req.app.locals.key, req.body.text).toString('base64') });
});

module.exports = { sealMessage };
