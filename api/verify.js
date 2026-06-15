const jwt = require('jsonwebtoken');
const https = require('https');
const crypto = require('crypto');

module.exports = async function handler(req, res) {
  res.status(200).json({ status: "Libraries loaded successfully" });
};
