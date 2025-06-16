const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class SecureRateLimiter {
  constructor(options = {}) {
    // Configurable options with more aggressive defaults
    this.windowMs = options.windowMs || 60 * 1000; // 1 minute
    this.maxRequests = options.maxRequests || 50; // More restrictive default
    this.delayThresholdMs = options.delayThresholdMs || 1000; // Slower threshold
    this.burstThreshold = options.burstThreshold || 5; // Much stricter burst detection
    this.burstWindowMs = options.burstWindowMs || 3 * 1000; // 3 seconds burst window
    this.suspiciousThreshold = options.suspiciousThreshold || 2; // Faster temp ban
    this.tempBanDurationMs = options.tempBanDurationMs || 30 * 60 * 1000; // 30 minutes
    this.strictMode = options.strictMode !== false; // Enable by default
    
    // Enhanced bot detection
    this.botKeywords = options.botKeywords || [
      'Googlebot', 'Bingbot', 'YandexBot', 'DuckDuckBot', 'Baiduspider',
      'curl', 'wget', 'python-requests', 'node-fetch', 'bot', 'crawler', 
      'spider', 'scraper', 'axios', 'http'
    ];

    // Enhanced stores with IP-based tracking
    this.requestStore = new Map(); // Fingerprint-based tracking
    this.ipRequestStore = new Map(); // IP-based tracking (primary)
    this.lastRequestTimestamps = new Map();
    this.fingerprintStore = new Map(); // Track multiple fingerprints per IP
    this.suspiciousActivity = new Map(); // Track suspicious behavior
    this.tempBans = new Map(); // Temporary bans
    this.burstTracker = new Map(); // Track burst requests
    this.ipHeaderTracker = new Map(); // Track IP header manipulation
    this.pathTracker = new Map(); // Track path-based patterns
    
    // Connection tracking
    this.connectionTracker = new Map();
    this.maxConnectionsPerIP = options.maxConnectionsPerIP || 10; // More restrictive

    // Progressive penalty system
    this.penaltyScores = new Map();
    this.maxPenaltyScore = options.maxPenaltyScore || 100;
    this.penaltyDecayRate = options.penaltyDecayRate || 10; // Points removed per minute

    // Logs setup
    this.logsDir = path.join(process.cwd(), 'logs');
    this.logFile = path.join(this.logsDir, 'requests.log');
    this.securityLogFile = path.join(this.logsDir, 'security.log');

    if (!fs.existsSync(this.logsDir)) {
      fs.mkdirSync(this.logsDir, { recursive: true });
    }

    // Cleanup interval
    this.setupCleanup();
  }

  // Enhanced fingerprinting with more factors
  getFingerprint(req) {
    const ip = this.getClientIP(req);
    const ua = req.headers['user-agent'] || 'none';
    const acceptLang = req.headers['accept-language'] || 'none';
    const acceptEnc = req.headers['accept-encoding'] || 'none';
    const accept = req.headers['accept'] || 'none';
    const connection = req.headers['connection'] || 'none';
    
    return crypto.createHash('sha256')
      .update(`${ip}:${ua}:${acceptLang}:${acceptEnc}:${accept}:${connection}`)
      .digest('hex');
  }

  // Enhanced IP extraction with validation
  getClientIP(req) {
    const forwardedFor = req.headers['x-forwarded-for'];
    const realIP = req.headers['x-real-ip'];
    const forwarded = req.headers['forwarded'];
    const connection = req.connection?.remoteAddress;
    const socket = req.socket?.remoteAddress;
    const reqIP = req.ip;

    let ip = 'unknown';

    // Prioritize real connection IP over headers (more secure)
    if (connection && !this.isPrivateIP(connection)) {
      ip = connection;
    } else if (socket && !this.isPrivateIP(socket)) {
      ip = socket;
    } else if (reqIP && !this.isPrivateIP(reqIP)) {
      ip = reqIP;
    } else if (forwardedFor) {
      const ips = forwardedFor.split(',').map(ip => ip.trim());
      ip = ips.find(ip => !this.isPrivateIP(ip)) || ips[0];
    } else if (realIP && !this.isPrivateIP(realIP)) {
      ip = realIP;
    } else if (forwarded) {
      const match = forwarded.match(/for=([^;,\s]+)/);
      if (match) ip = match[1];
    }

    return ip;
  }

  // Check if IP is private/local
  isPrivateIP(ip) {
    if (!ip) return true;
    ip = ip.replace(/^::ffff:/, ''); // Remove IPv6 prefix
    
    const privateRanges = [
      /^127\./, // Loopback
      /^10\./, // Private class A
      /^172\.(1[6-9]|2[0-9]|3[01])\./, // Private class B
      /^192\.168\./, // Private class C
      /^169\.254\./, // Link-local
      /^::1$/, // IPv6 loopback
      /^fe80::/i // IPv6 link-local
    ];
    
    return privateRanges.some(range => range.test(ip));
  }

  // Enhanced IP spoofing detection
  detectIPSpoofing(req) {
    const ip = this.getClientIP(req);
    const headers = req.headers;
    
    // Track different IP headers from same source
    const ipHeaders = {
      'x-forwarded-for': headers['x-forwarded-for'],
      'x-real-ip': headers['x-real-ip'],
      'forwarded': headers['forwarded'],
      'via': headers['via']
    };

    let headerCount = 0;
    let uniqueIPs = new Set();
    
    Object.values(ipHeaders).forEach(header => {
      if (header) {
        headerCount++;
        if (header.includes(',')) {
          header.split(',').forEach(ip => uniqueIPs.add(ip.trim()));
        } else {
          uniqueIPs.add(header.trim());
        }
      }
    });

    // Track IP header patterns per IP
    const pattern = Object.keys(ipHeaders).filter(key => ipHeaders[key]).join(',');
    const tracker = this.ipHeaderTracker.get(ip) || new Set();
    tracker.add(pattern);
    this.ipHeaderTracker.set(ip, tracker);

    // Suspicious if too many different patterns or headers
    return headerCount > 3 || uniqueIPs.size > 5 || tracker.size > 3;
  }

  // Enhanced path-based attack detection
  detectPathManipulation(req) {
    const ip = this.getClientIP(req);
    const url = req.url || req.path || '/';
    
    // Track unique paths per IP
    const paths = this.pathTracker.get(ip) || new Set();
    paths.add(url);
    this.pathTracker.set(ip, paths);
    
    // Check for query parameter manipulation (common in scripts)
    const hasQueryParams = url.includes('?');
    const queryParamCount = (url.match(/[?&]/g) || []).length;
    
    // Suspicious if too many unique paths or complex query manipulation
    return paths.size > 20 || queryParamCount > 10;
  }

  // Progressive penalty system
  addPenalty(ip, points, reason) {
    const current = this.penaltyScores.get(ip) || { score: 0, lastUpdate: Date.now() };
    current.score += points;
    current.lastUpdate = Date.now();
    current.reason = reason;
    
    this.penaltyScores.set(ip, current);
    
    if (current.score >= this.maxPenaltyScore) {
      this.addTempBan(ip, `Penalty threshold exceeded: ${reason}`);
      return true;
    }
    
    return false;
  }

  // Decay penalty scores over time
  decayPenalties() {
    const now = Date.now();
    for (const [ip, penalty] of this.penaltyScores.entries()) {
      const minutesPassed = (now - penalty.lastUpdate) / (60 * 1000);
      const decayAmount = Math.floor(minutesPassed * this.penaltyDecayRate);
      
      if (decayAmount > 0) {
        penalty.score = Math.max(0, penalty.score - decayAmount);
        penalty.lastUpdate = now;
        
        if (penalty.score === 0) {
          this.penaltyScores.delete(ip);
        } else {
          this.penaltyScores.set(ip, penalty);
        }
      }
    }
  }

  // Enhanced logging with security events
  logRequest(req, classification, details = '') {
    const timestamp = new Date().toISOString();
    const ip = this.getClientIP(req);
    const ua = req.headers['user-agent'] || 'none';
    const path = req.url || req.path || '/';
    const penalty = this.penaltyScores.get(ip)?.score || 0;
    const logEntry = `${timestamp} | IP: ${ip} | UA: ${ua} | Path: ${path} | Status: ${classification} | Penalty: ${penalty} | ${details}\n`;

    try {
      fs.appendFileSync(this.logFile, logEntry, { flag: 'a' });
      
      if (['blocked', 'suspicious', 'temp-banned', 'ip-spoofing', 'penalty-ban'].includes(classification)) {
        fs.appendFileSync(this.securityLogFile, logEntry, { flag: 'a' });
      }
    } catch (error) {
      console.error('Logging error:', error);
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
    const existing = this.tempBans.get(ip);
    this.tempBans.set(ip, { 
      timestamp: Date.now(), 
      reason,
      attempts: (existing?.attempts || 0) + 1
    });
  }

  // Track suspicious activity with enhanced scoring
  trackSuspiciousActivity(ip, reason, penaltyPoints = 10) {
    const current = this.suspiciousActivity.get(ip) || { count: 0, reasons: [] };
    current.count++;
    current.reasons.push(reason);
    current.lastActivity = Date.now();
    
    this.suspiciousActivity.set(ip, current);
    
    // Add penalty points
    if (this.addPenalty(ip, penaltyPoints, reason)) {
      return true; // Banned due to penalty
    }
    
    if (current.count >= this.suspiciousThreshold) {
      this.addTempBan(ip, `Suspicious activity: ${current.reasons.join(', ')}`);
      return true;
    }
    
    return false;
  }

  // Enhanced rate limiting with dual tracking (IP + fingerprint)
  rateLimit(req) {
    const fingerprint = this.getFingerprint(req);
    const ip = this.getClientIP(req);
    const now = Date.now();

    // Check temp ban first
    if (this.isTempBanned(ip)) {
      this.logRequest(req, 'temp-banned', 'IP temporarily banned');
      return { allowed: false, reason: 'Temporarily banned', httpCode: 429 };
    }

    // PRIMARY: IP-based rate limiting (more reliable)
    let ipEntry = this.ipRequestStore.get(ip);
    if (!ipEntry || now - ipEntry.lastReset > this.windowMs) {
      ipEntry = { count: 1, lastReset: now };
      this.ipRequestStore.set(ip, ipEntry);
    } else {
      ipEntry.count++;
      if (ipEntry.count > this.maxRequests) {
        if (this.trackSuspiciousActivity(ip, 'ip-rate-limit-exceeded', 20)) {
          return { allowed: false, reason: 'Temporarily banned for rate limit violations', httpCode: 429 };
        }
        this.logRequest(req, 'blocked', 'IP rate limit exceeded');
        return { allowed: false, reason: 'Rate limit exceeded', httpCode: 429 };
      }
    }

    // SECONDARY: Fingerprint-based tracking (backup)
    let fingerprintEntry = this.requestStore.get(fingerprint);
    if (!fingerprintEntry || now - fingerprintEntry.lastReset > this.windowMs) {
      fingerprintEntry = { count: 1, lastReset: now, ip };
      this.requestStore.set(fingerprint, fingerprintEntry);
    } else {
      fingerprintEntry.count++;
      if (fingerprintEntry.count > this.maxRequests * 1.5) { // More lenient for fingerprints
        if (this.trackSuspiciousActivity(ip, 'fingerprint-rate-limit-exceeded', 15)) {
          return { allowed: false, reason: 'Temporarily banned', httpCode: 429 };
        }
        this.logRequest(req, 'blocked', 'Fingerprint rate limit exceeded');
        return { allowed: false, reason: 'Rate limit exceeded', httpCode: 429 };
      }
    }

    // Burst detection (per IP)
    let burstEntry = this.burstTracker.get(ip);
    if (!burstEntry || now - burstEntry.windowStart > this.burstWindowMs) {
      burstEntry = { count: 1, windowStart: now };
    } else {
      burstEntry.count++;
      if (burstEntry.count > this.burstThreshold) {
        if (this.trackSuspiciousActivity(ip, 'burst-requests', 25)) {
          return { allowed: false, reason: 'Temporarily banned for burst activity', httpCode: 429 };
        }
        this.logRequest(req, 'blocked', 'Burst limit exceeded');
        return { allowed: false, reason: 'Too many requests in short time', httpCode: 429 };
      }
    }
    this.burstTracker.set(ip, burstEntry);

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
    
    if (hasBot) {
      this.trackSuspiciousActivity(ip, 'bot-user-agent', 30);
      return true;
    }

    // Enhanced pattern-based detection
    // 1. Missing or suspicious User-Agent
    if (!ua || ua.length < 10 || ua === 'none' || ua.includes('http') || ua.includes('curl')) {
      this.trackSuspiciousActivity(ip, 'suspicious-user-agent', 25);
      return true;
    }

    // 2. Missing critical headers (legitimate browsers always send these)
    const requiredHeaders = ['accept', 'accept-language', 'accept-encoding'];
    const missingHeaders = requiredHeaders.filter(header => !req.headers[header]);
    
    if (missingHeaders.length >= 2) {
      this.trackSuspiciousActivity(ip, `missing-headers-${missingHeaders.join(',')}`, 20);
      return true;
    }

    // 3. Suspicious header combinations
    const accept = req.headers.accept || '';
    if (accept.includes('*/*') && accept.length < 10) {
      this.trackSuspiciousActivity(ip, 'simple-accept-header', 15);
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
    
    // Too fast requests (script-like) - More aggressive detection
    if (lastTimestamp > 0 && timeDiff < this.delayThresholdMs) {
      if (this.trackSuspiciousActivity(ip, 'too-fast-requests', 20)) {
        return true;
      }
      return true;
    }

    // Check for multiple fingerprints from same IP (rotating user agents)
    const ipFingerprints = this.fingerprintStore.get(ip) || new Set();
    ipFingerprints.add(fingerprint);
    this.fingerprintStore.set(ip, ipFingerprints);
    
    // More aggressive fingerprint tracking
    if (ipFingerprints.size > 3) {
      this.trackSuspiciousActivity(ip, `multiple-fingerprints-${ipFingerprints.size}`, 15);
      return true;
    }

    return false;
  }

  // Track concurrent connections per IP
  trackConnection(req) {
    const ip = this.getClientIP(req);
    const current = this.connectionTracker.get(ip) || 0;
    
    if (current >= this.maxConnectionsPerIP) {
      this.trackSuspiciousActivity(ip, 'too-many-connections', 20);
      return false;
    }
    
    this.connectionTracker.set(ip, current + 1);
    
    // Clean up connection when response ends
    const cleanup = () => {
      const count = this.connectionTracker.get(ip) || 1;
      if (count <= 1) {
        this.connectionTracker.delete(ip);
      } else {
        this.connectionTracker.set(ip, count - 1);
      }
    };

    req.on('close', cleanup);
    req.on('end', cleanup);
    
    return true;
  }

  // Setup cleanup intervals
  setupCleanup() {
    // Clean up old entries every 2 minutes
    setInterval(() => {
      const now = Date.now();
      
      // Clean rate limit stores
      [this.requestStore, this.ipRequestStore].forEach(store => {
        for (const [key, entry] of store.entries()) {
          if (now - entry.lastReset > this.windowMs * 2) {
            store.delete(key);
          }
        }
      });
      
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
      
      // Clean suspicious activity (after 30 minutes)
      for (const [key, entry] of this.suspiciousActivity.entries()) {
        if (now - entry.lastActivity > 30 * 60 * 1000) {
          this.suspiciousActivity.delete(key);
        }
      }

      // Clean path tracker (after 1 hour)
      for (const [key, paths] of this.pathTracker.entries()) {
        if (paths.size === 0 || now - (this.lastRequestTimestamps.get(key) || 0) > 60 * 60 * 1000) {
          this.pathTracker.delete(key);
        }
      }

      // Decay penalty scores
      this.decayPenalties();
      
    }, 2 * 60 * 1000); // Every 2 minutes
  }

  // Enhanced middleware with comprehensive protection
  middleware() {
    return (req, res, next) => {
      const ip = this.getClientIP(req);
      
      try {
        // 1. Check connection limit
        if (!this.trackConnection(req)) {
          this.logRequest(req, 'blocked', 'Too many connections');
          res.status(503).send('Service Temporarily Unavailable');
          return;
        }

        // 2. Check for IP spoofing
        if (this.detectIPSpoofing(req)) {
          this.logRequest(req, 'blocked', 'IP spoofing detected');
          this.trackSuspiciousActivity(ip, 'ip-spoofing', 30);
          res.status(403).send('Forbidden');
          return;
        }

        // 3. Check for path manipulation
        if (this.strictMode && this.detectPathManipulation(req)) {
          this.logRequest(req, 'blocked', 'Path manipulation detected');
          this.trackSuspiciousActivity(ip, 'path-manipulation', 20);
          res.status(403).send('Forbidden');
          return;
        }

        // 4. Check rate limit (includes temp ban check)
        const rateLimitResult = this.rateLimit(req);
        if (!rateLimitResult.allowed) {
          res.status(rateLimitResult.httpCode || 429).send(rateLimitResult.reason);
          return;
        }

        // 5. Block bots (before behavioral analysis)
        if (this.isBot(req)) {
          this.logRequest(req, 'blocked', 'Bot detected');
          res.status(403).send('Forbidden');
          return;
        }

        // 6. Block script-like behavior
        if (this.isScriptLike(req)) {
          this.logRequest(req, 'blocked', 'Script-like behavior');
          res.status(429).send('Too Many Requests');
          return;
        }

        // Legitimate request
        this.logRequest(req, 'allowed');
        next();

      } catch (error) {
        console.error('Rate limiter error:', error);
        // Fail open for reliability, but log the error
        this.logRequest(req, 'error', `Middleware error: ${error.message}`);
        next();
      }
    };
  }

  // Get comprehensive statistics
  getStats() {
    return {
      totalFingerprints: this.requestStore.size,
      totalIPs: this.ipRequestStore.size,
      tempBannedIPs: this.tempBans.size,
      suspiciousIPs: this.suspiciousActivity.size,
      penalizedIPs: this.penaltyScores.size,
      activeConnections: Array.from(this.connectionTracker.values()).reduce((a, b) => a + b, 0),
      pathTrackingEntries: this.pathTracker.size,
      ipHeaderPatterns: this.ipHeaderTracker.size
    };
  }

  // Enhanced manual IP management
  banIP(ip, reason = 'Manual ban', duration = null) {
    this.addTempBan(ip, reason);
    if (duration) {
      setTimeout(() => this.unbanIP(ip), duration);
    }
  }

  unbanIP(ip) {
    this.tempBans.delete(ip);
    this.suspiciousActivity.delete(ip);
    this.penaltyScores.delete(ip);
  }

  // Get detailed IP information
  getIPInfo(ip) {
    return {
      isBanned: this.isTempBanned(ip),
      banInfo: this.tempBans.get(ip),
      suspiciousActivity: this.suspiciousActivity.get(ip),
      penaltyScore: this.penaltyScores.get(ip),
      fingerprints: this.fingerprintStore.get(ip)?.size || 0,
      connections: this.connectionTracker.get(ip) || 0,
      requests: this.ipRequestStore.get(ip),
      headerPatterns: this.ipHeaderTracker.get(ip)?.size || 0
    };
  }
}

module.exports = SecureRateLimiter;