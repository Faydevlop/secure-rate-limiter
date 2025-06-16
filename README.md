# Secure Rate Limiter 🛡️

Advanced rate-limiting middleware for Node.js with comprehensive bot detection, behavioral analysis, and DDoS protection.

## Features

- **Multi-layered Protection**: Rate limiting, burst detection, behavioral analysis
- **Advanced Bot Detection**: Pattern-based detection beyond simple user-agent checks
- **IP Spoofing Detection**: Identifies suspicious header manipulation
- **Temporary Banning**: Progressive punishment system for repeat offenders
- **Connection Limiting**: Prevents connection flooding attacks
- **Behavioral Analysis**: Detects script-like timing patterns and fingerprint rotation
- **Comprehensive Logging**: Security event logging with detailed analytics
- **Memory Efficient**: Automatic cleanup of old tracking data

## Installation

```bash
npm install secure-rate-limiter
```

## Quick Start

```javascript
const express = require('express');
const SecureRateLimiter = require('secure-rate-limiter');

const app = express();

// Initialize with default settings
const limiter = new SecureRateLimiter();

// Apply to all routes
app.use(limiter.middleware());

// Or apply to specific routes
app.get('/api/*', limiter.middleware(), (req, res) => {
  res.json({ message: 'API endpoint protected' });
});

app.listen(3000);
```

## Configuration

```javascript
const limiter = new SecureRateLimiter({
  windowMs: 60 * 1000,           // Time window (1 minute)
  maxRequests: 50,               // Max requests per window
  burstThreshold: 10,            // Max requests in burst window
  burstWindowMs: 5 * 1000,       // Burst detection window (5 seconds)
  delayThresholdMs: 500,         // Min delay between requests (ms)
  suspiciousThreshold: 3,        // Strikes before temp ban
  tempBanDurationMs: 10 * 60 * 1000, // Temp ban duration (10 minutes)
  maxConnectionsPerIP: 20,       // Max concurrent connections per IP
  botKeywords: [                 // Additional bot detection keywords
    'mybot', 'scraper'
  ]
});
```

## Advanced Usage

### Manual IP Management

```javascript
// Ban an IP manually
limiter.banIP('192.168.1.100', 'Suspicious activity');

// Unban an IP
limiter.unbanIP('192.168.1.100');

// Get current statistics
const stats = limiter.getStats();
console.log(stats);
// {
//   totalFingerprints: 150,
//   tempBannedIPs: 5,
//   suspiciousIPs: 12,
//   activeConnections: 45
// }
```

### Custom Bot Detection

```javascript
const limiter = new SecureRateLimiter({
  botKeywords: [
    'Googlebot', 'Bingbot', 'curl', 'wget',
    'python-requests', 'scrapy', 'selenium'
  ]
});
```

### Environment-Specific Configuration

```javascript
// Development - More lenient
const devLimiter = new SecureRateLimiter({
  maxRequests: 1000,
  burstThreshold: 50,
  tempBanDurationMs: 60 * 1000 // 1 minute
});

// Production - Strict security
const prodLimiter = new SecureRateLimiter({
  maxRequests: 30,
  burstThreshold: 5,
  delayThresholdMs: 1000,
  tempBanDurationMs: 30 * 60 * 1000 // 30 minutes
});
```

## Protection Mechanisms

### 1. Rate Limiting
- Tracks requests per IP/fingerprint combination
- Configurable time windows and request limits
- Progressive enforcement with temporary bans

### 2. Burst Detection
- Monitors rapid-fire requests in short time windows
- Separate threshold for burst vs sustained traffic
- Immediate blocking of burst attacks

### 3. Bot Detection
- User-Agent analysis with keyword matching
- Header pattern analysis (missing standard headers)
- Behavioral fingerprinting

### 4. Behavioral Analysis
- Request timing analysis to detect scripts
- User-Agent rotation detection
- Multiple fingerprint tracking per IP

### 5. Connection Limiting
- Prevents connection flooding
- Per-IP concurrent connection limits
- Automatic cleanup on connection close

### 6. IP Spoofing Detection
- Analyzes conflicting IP headers
- Detects header manipulation attempts
- Blocks requests with suspicious header combinations

## Logging

The middleware creates detailed logs in the `logs/` directory:

- `requests.log` - All requests with classifications
- `security.log` - Security events only (blocks, bans, suspicious activity)

Log format:
```
2024-01-15T10:30:45.123Z | IP: 192.168.1.100 | UA: Mozilla/5.0... | Status: blocked | Burst limit exceeded
```

## Performance Considerations

- **Memory Usage**: Automatic cleanup prevents memory leaks
- **CPU Impact**: Minimal overhead with efficient algorithms
- **Scalability**: Designed for high-traffic applications
- **Cleanup**: Automatic cleanup every 5 minutes removes stale data

## Integration Examples

### Express.js
```javascript
const express = require('express');
const SecureRateLimiter = require('secure-rate-limiter');

const app = express();
const limiter = new SecureRateLimiter();

app.use(limiter.middleware());
```

### Koa.js
```javascript
const Koa = require('koa');
const SecureRateLimiter = require('secure-rate-limiter');

const app = new Koa();
const limiter = new SecureRateLimiter();

app.use(async (ctx, next) => {
  return new Promise((resolve, reject) => {
    limiter.middleware()(ctx.req, ctx.res, (err) => {
      if (err) reject(err);
      else resolve(next());
    });
  });
});
```

## Testing Against Attacks

The middleware has been tested against various attack patterns:
- High-volume request floods
- Rotating User-Agent attacks
- IP header spoofing
- Distributed attacks with multiple IPs
- Timing-based evasion attempts

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
- GitHub Issues: [Report a bug](https://github.com/faydevlop/secure-rate-limiter/issues)
- Documentation: See examples above
- Version: 2.0.0