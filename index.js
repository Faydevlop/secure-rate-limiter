const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class SecureRateLimiter {
  constructor(options = {}) {
    // Configurable options with more aggressive defaults
    this.windowMs = options.windowMs || 60 * 1000; // 1 minute
    this.maxRequests = options.maxRequests || 50; // Reduced from 100
    this.delayThresholdMs = options.delayThresholdMs || 500; // Increased threshold
    this.burstThreshold = options.burstThreshold || 10; // Max requests in burst window
    this.burstWindowMs = options.burstWindowMs || 5 * 1000; // 5 seconds burst window
    this.suspiciousThreshold = options.suspiciousThreshold || 3; // Strikes before temp ban
    this.tempBanDurationMs = options.tempBanDurationMs || 10 * 60 * 1000; // 10 minutes
    
    this.botKeywords = options.botKeywords || [
      'Googlebot', 'Bingbot', 'YandexBot', 'DuckDuckBot', 'Baiduspider',
      'curl', 'wget', 'python-requests', 'node-fetch', 'bot', 'crawler', 'spider'
    ];

    // Enhanced stores
    this.requestStore = new Map();
    this.lastRequestTimestamps = new Map();
    this.fingerprintStore = new Map(); // Track multiple fingerprints per IP
    this.suspiciousActivity = new Map(); // Track suspicious behavior
    this.tempBans = new Map(); // Temporary bans
    this.burstTracker = new Map(); // Track burst requests
    
    // Connection tracking
    this.connectionTracker = new Map();
    this.maxConnectionsPerIP = options.maxConnectionsPerIP || 20;

    // Logs setup
    this.logsDir = path.join(__dirname, 'logs');
    this.logFile = path.join(this.logsDir, 'requests.log');
    this.securityLogFile = path.join(this.logsDir, 'security.log');

    if (!fs.existsSync(this.logsDir)) {
      fs.mkdirSync(this.logsDir, { recursive: true });
    }

    // Cleanup interval
    this.setupCleanup();
  }

  // Enhanced fingerprinting with multiple factors
  getFingerprint(req) {
    const ip = this.getClientIP(req);
    const ua = req.headers['user-agent'] || 'none';
    const acceptLang = req.headers['accept-language'] || 'none';
    const acceptEnc = req.headers['accept-encoding'] || 'none';
    
    return crypto.createHash('sha256')
      .update(`${ip}:${ua}:${acceptLang}:${acceptEnc}`)
      .digest('hex');
  }

  // Better IP extraction considering proxies/load balancers
  getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
           req.headers['x-real-ip'] ||
           req.connection?.remoteAddress ||
           req.socket?.remoteAddress ||
           req.ip ||
           'unknown';
  }

  // Detect IP spoofing attempts
  detectIPSpoofing(req) {
    const forwardedFor = req.headers['x-forwarded-for'];
    const realIP = req.headers['x-real-ip'];
    const forwarded = req.headers['forwarded'];
    
    // Check for multiple conflicting IP headers (common in attack scripts)
    let ipHeaders = 0;
    if (forwardedFor) ipHeaders++;
    if (realIP) ipHeaders++;
    if (forwarded) ipHeaders++;
    
    return ipHeaders > 2; // Suspicious if too many IP headers
  }

  // Enhanced logging with security events
  logRequest(req, classification, details = '') {
    const timestamp = new Date().toISOString();
    const ip = this.getClientIP(req);
    const ua = req.headers['user-agent'] || 'none';
    const logEntry = `${timestamp} | IP: ${ip} | UA: ${ua} | Status: ${classification} | ${details}\n`;

    fs.appendFileSync(this.logFile, logEntry, { flag: 'a' });
    
    if (['blocked', 'suspicious', 'temp-banned', 'ip-spoofing'].includes(classification)) {
      fs.appendFileSync(this.securityLogFile, logEntry, { flag: 'a' });
    }
  }

  // Check if IP is temporarily banned
  isTempBanned(ip) {
    const banInfo = this.tempBans.get(ip);
    if (!banInfo) return false;
    
    if (Date.now() - banInfo.timestamp > this.tempBanDurationMs) {
      this.tempBans.delete(ip);
      return false;
    }
    
    return true;
  }

  // Add IP to temporary ban list
  addTempBan(ip, reason) {
    this.tempBans.set(ip, { 
      timestamp: Date.now(), 
      reason,
      attempts: (this.tempBans.get(ip)?.attempts || 0) + 1
    });
  }

  // Track suspicious activity
  trackSuspiciousActivity(ip, reason) {
    const current = this.suspiciousActivity.get(ip) || { count: 0, reasons: [] };
    current.count++;
    current.reasons.push(reason);
    current.lastActivity = Date.now();
    
    this.suspiciousActivity.set(ip, current);
    
    if (current.count >= this.suspiciousThreshold) {
      this.addTempBan(ip, `Suspicious activity: ${current.reasons.join(', ')}`);
      return true;
    }
    
    return false;
  }

  // Enhanced rate limiting with burst detection
  rateLimit(req) {
    const fingerprint = this.getFingerprint(req);
    const ip = this.getClientIP(req);
    const now = Date.now();

    // Check temp ban first
    if (this.isTempBanned(ip)) {
      this.logRequest(req, 'temp-banned', 'IP temporarily banned');
      return { allowed: false, reason: 'Temporarily banned' };
    }

    // Burst detection
    let burstEntry = this.burstTracker.get(ip);
    if (!burstEntry || now - burstEntry.windowStart > this.burstWindowMs) {
      burstEntry = { count: 1, windowStart: now };
    } else {
      burstEntry.count++;
      if (burstEntry.count > this.burstThreshold) {
        if (this.trackSuspiciousActivity(ip, 'burst-requests')) {
          return { allowed: false, reason: 'Temporarily banned for burst activity' };
        }
        this.logRequest(req, 'blocked', 'Burst limit exceeded');
        return { allowed: false, reason: 'Too many requests in short time' };
      }
    }
    this.burstTracker.set(ip, burstEntry);

    // Regular rate limiting
    let entry = this.requestStore.get(fingerprint);
    if (!entry || now - entry.lastReset > this.windowMs) {
      entry = { count: 1, lastReset: now, ip };
      this.requestStore.set(fingerprint, entry);
    } else {
      entry.count++;
      if (entry.count > this.maxRequests) {
        if (this.trackSuspiciousActivity(ip, 'rate-limit-exceeded')) {
          return { allowed: false, reason: 'Temporarily banned for rate limit violations' };
        }
        this.logRequest(req, 'blocked', 'Rate limit exceeded');
        return { allowed: false, reason: 'Rate limit exceeded' };
      }
    }

    return { allowed: true };
  }

  // Enhanced bot detection with pattern analysis
  isBot(req) {
    const ua = req.headers['user-agent'] || '';
    const ip = this.getClientIP(req);
    
    // Direct bot keyword detection
    const hasBot = this.botKeywords.some(keyword => 
      ua.toLowerCase().includes(keyword.toLowerCase())
    );
    
    if (hasBot) return true;

    // Pattern-based detection
    // 1. Missing or suspicious User-Agent
    if (!ua || ua.length < 10 || ua === 'none') {
      this.trackSuspiciousActivity(ip, 'suspicious-user-agent');
      return true;
    }

    // 2. Unusual header combinations
    const hasAccept = req.headers.accept;
    const hasAcceptLang = req.headers['accept-language'];
    const hasAcceptEnc = req.headers['accept-encoding'];
    
    if (!hasAccept && !hasAcceptLang && !hasAcceptEnc) {
      this.trackSuspiciousActivity(ip, 'missing-standard-headers');
      return true;
    }

    return false;
  }

  // Enhanced behavioral analysis
  isScriptLike(req) {
    const fingerprint = this.getFingerprint(req);
    const ip = this.getClientIP(req);
    const now = Date.now();
    const lastTimestamp = this.lastRequestTimestamps.get(fingerprint) || 0;
    
    this.lastRequestTimestamps.set(fingerprint, now);
    
    const timeDiff = now - lastTimestamp;
    
    // Too fast requests (script-like)
    if (lastTimestamp > 0 && timeDiff < this.delayThresholdMs) {
      this.trackSuspiciousActivity(ip, 'too-fast-requests');
      return true;
    }

    // Check for multiple fingerprints from same IP (rotating user agents)
    const ipFingerprints = this.fingerprintStore.get(ip) || new Set();
    ipFingerprints.add(fingerprint);
    this.fingerprintStore.set(ip, ipFingerprints);
    
    // If too many different fingerprints from same IP, it's suspicious
    if (ipFingerprints.size > 5) {
      this.trackSuspiciousActivity(ip, 'multiple-fingerprints');
      return true;
    }

    return false;
  }

  // Track concurrent connections per IP
  trackConnection(req) {
    const ip = this.getClientIP(req);
    const current = this.connectionTracker.get(ip) || 0;
    
    if (current >= this.maxConnectionsPerIP) {
      this.trackSuspiciousActivity(ip, 'too-many-connections');
      return false;
    }
    
    this.connectionTracker.set(ip, current + 1);
    
    // Clean up connection when response ends
    req.on('close', () => {
      const count = this.connectionTracker.get(ip) || 1;
      if (count <= 1) {
        this.connectionTracker.delete(ip);
      } else {
        this.connectionTracker.set(ip, count - 1);
      }
    });
    
    return true;
  }

  // Setup cleanup intervals
  setupCleanup() {
    // Clean up old entries every 5 minutes
    setInterval(() => {
      const now = Date.now();
      
      // Clean rate limit store
      for (const [key, entry] of this.requestStore.entries()) {
        if (now - entry.lastReset > this.windowMs * 2) {
          this.requestStore.delete(key);
        }
      }
      
      // Clean timestamps
      for (const [key, timestamp] of this.lastRequestTimestamps.entries()) {
        if (now - timestamp > this.windowMs * 2) {
          this.lastRequestTimestamps.delete(key);
        }
      }
      
      // Clean burst tracker
      for (const [key, entry] of this.burstTracker.entries()) {
        if (now - entry.windowStart > this.burstWindowMs * 2) {
          this.burstTracker.delete(key);
        }
      }
      
      // Clean suspicious activity (after 1 hour)
      for (const [key, entry] of this.suspiciousActivity.entries()) {
        if (now - entry.lastActivity > 60 * 60 * 1000) {
          this.suspiciousActivity.delete(key);
        }
      }
      
    }, 5 * 60 * 1000); // Every 5 minutes
  }

  // Enhanced middleware
  middleware() {
    return (req, res, next) => {
      const ip = this.getClientIP(req);
      
      // 1. Check connection limit
      if (!this.trackConnection(req)) {
        this.logRequest(req, 'blocked', 'Too many connections');
        res.status(429).send('Too Many Connections');
        return;
      }

      // 2. Check for IP spoofing
      if (this.detectIPSpoofing(req)) {
        this.logRequest(req, 'blocked', 'IP spoofing detected');
        this.trackSuspiciousActivity(ip, 'ip-spoofing');
        res.status(403).send('Forbidden: Invalid headers');
        return;
      }

      // 3. Check rate limit (includes temp ban check)
      const rateLimitResult = this.rateLimit(req);
      if (!rateLimitResult.allowed) {
        res.status(429).send(rateLimitResult.reason);
        return;
      }

      // 4. Block bots
      if (this.isBot(req)) {
        this.logRequest(req, 'blocked', 'Bot detected');
        res.status(403).send('Forbidden: Bot detected');
        return;
      }

      // 5. Block script-like behavior
      if (this.isScriptLike(req)) {
        this.logRequest(req, 'blocked', 'Script-like behavior');
        res.status(429).send('Too Fast: Script-like behavior detected');
        return;
      }

      // Legitimate request
      this.logRequest(req, 'allowed');
      next();
    };
  }

  // Get statistics
  getStats() {
    return {
      totalFingerprints: this.requestStore.size,
      tempBannedIPs: this.tempBans.size,
      suspiciousIPs: this.suspiciousActivity.size,
      activeConnections: Array.from(this.connectionTracker.values()).reduce((a, b) => a + b, 0)
    };
  }

  // Manual IP ban/unban methods
  banIP(ip, reason = 'Manual ban') {
    this.addTempBan(ip, reason);
  }

  unbanIP(ip) {
    this.tempBans.delete(ip);
    this.suspiciousActivity.delete(ip);
  }
}

module.exports = SecureRateLimiter;