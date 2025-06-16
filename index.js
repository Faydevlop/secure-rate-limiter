const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class SecureRateLimiter {
  constructor(options = {}) {
    // Configurable options
    this.windowMs = options.windowMs || 60 * 1000; // 1 minute
    this.maxRequests = options.maxRequests || 100;
    this.delayThresholdMs = options.delayThresholdMs || 200;
    this.botKeywords = options.botKeywords || [
      'Googlebot', 'Bingbot', 'YandexBot', 'DuckDuckBot', 'Baiduspider',
      'curl', 'wget', 'python-requests', 'node-fetch'
    ];

    // Stores for rate limiting and behavioral analysis
    this.requestStore = new Map();
    this.lastRequestTimestamps = new Map();

    // Logs directory setup
    this.logsDir = path.join(__dirname, 'logs');
    this.logFile = path.join(this.logsDir, 'requests.log');

    if (!fs.existsSync(this.logsDir)) {
      fs.mkdirSync(this.logsDir, { recursive: true });
    }
  }

  // Generate a fingerprint for the request (IP + User-Agent)
  getFingerprint(req) {
    const ip = req.socket.remoteAddress;
    const ua = req.headers['user-agent'] || 'none';
    return crypto.createHash('sha256').update(`${ip}:${ua}`).digest('hex');
  }

  // Log requests with classification
  logRequest(req, classification) {
    const timestamp = new Date().toISOString();
    const ip = req.socket.remoteAddress;
    const ua = req.headers['user-agent'] || 'none';
    const logEntry = `${timestamp} | IP: ${ip} | UA: ${ua} | Status: ${classification}\n`;

    fs.appendFileSync(this.logFile, logEntry, { flag: 'a' });
  }

  // Rate limiting logic
  rateLimit(req) {
    const fingerprint = this.getFingerprint(req);
    const now = Date.now();
    let entry = this.requestStore.get(fingerprint);

    if (!entry || now - entry.lastReset > this.windowMs) {
      entry = { count: 1, lastReset: now };
      this.requestStore.set(fingerprint, entry);
    } else {
      entry.count++;
      if (entry.count > this.maxRequests) {
        this.logRequest(req, 'rate-limited');
        return { allowed: false, reason: 'Rate limit exceeded' };
      }
    }
    return { allowed: true };
  }

  // Bot detection
  isBot(req) {
    const ua = req.headers['user-agent'] || '';
    return this.botKeywords.some(keyword => ua.includes(keyword));
  }

  // Behavioral analysis (detect script-like timing)
  isScriptLike(req) {
    const fingerprint = this.getFingerprint(req);
    const now = Date.now();
    const lastTimestamp = this.lastRequestTimestamps.get(fingerprint) || 0;
    this.lastRequestTimestamps.set(fingerprint, now);

    return (now - lastTimestamp < this.delayThresholdMs);
  }

  // Middleware for Express/Connect
  middleware() {
    return (req, res, next) => {
      // 1. Check rate limit
      const rateLimitResult = this.rateLimit(req);
      if (!rateLimitResult.allowed) {
        res.status(429).send('Too Many Requests');
        return;
      }

      // 2. Block bots
      if (this.isBot(req)) {
        this.logRequest(req, 'bot');
        res.status(403).send('Forbidden: Bot detected');
        return;
      }

      // 3. Block script-like behavior
      if (this.isScriptLike(req)) {
        this.logRequest(req, 'script-like');
        res.status(429).send('Too Fast: Script-like behavior');
        return;
      }

      // Legitimate request
      this.logRequest(req, 'real');
      next();
    };
  }
}

module.exports = SecureRateLimiter;
