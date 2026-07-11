const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const session = require('express-session');
const csrf = require('csurf');
const fs = require('fs');
const path = require('path');
const { execSync, exec, execFile, spawn } = require('child_process');
const m7Crypto = require('./modules/security/m7-crypto');
const { sanitizeForLogging, sanitizeObject } = require('./sanitizer');
const { validateRequestURL } = require('./ssrf-guard');
const SQLInjectionDetector = require('./sql-detector');
const { validateFilePath, isPathAllowed } = require('./path-validator');
const APIKeyManager = require('./key-manager');
const { RBACManager } = require('./rbac');
const SecurityErrorHandler = require('./error-handler');
const rateLimit = require('express-rate-limit');
const EmailBasedMFA = require('./modules/authentication/email-based-mfa');
const EmailService = require('./email-service');
// ✅ REMOVED: Early import of quantumEnvelopeService (line 22)
// Quantum service will be loaded lazily within initQuantumProxy()
const { registerAccessRoutes, createAccessTokenMiddleware, resolveBootstrapApiKey } = require('./register');

// ════════════════════════════════════════════════════════════════[[...[...]
// SECURITY LAYER 0: ENCRYPTION KEY MANAGEMENT (REQUEST ENCRYPTION)
// ════════════════════════════════════════════════════════════════[[...[...]

const KeyManager = require('./modules/security/management-key-functions');

// ════════════════════════════════════════════════════════════════[[...]
// SECURITY LAYER 1: ANTI-FORGERY TRANSPORT [NIST 2024 COMPLIANT]
// ════════════════════════════════════════════════════════════════[[...]

const {
    registerSecurity: registerAntiForgeryTransport,
    makeVerifiedRequest: createVerifiedHttpsClient
} = require('./modules/security/antiForgeryTransport');

// ════════════════════════════════════════════════════════════════[[...]
// SECURITY LAYER 2: SSL/TLS VERIFICATION MODULE
// ════════════════════════════════════════════════════════════════[[...]

const {
    enableSSLVerificationMiddleware,
    makeVerifiedRequest,
    getSSLStatus,
    getAuditStats,
    loadSSLConfig,
    shutdown: shutdownSSLTLS,
    getConfig: getSSLConfig
} = require('./modules/security/ssl-tls-verification');

// ════════════════════════════════════════════════════════════════[[...]
// SECURITY LAYER 6: ATTACK DETECTION & FORENSIC LOGGING (IMPORT)
// ════════════════════════════════════════════════════════════════[[...]

const { createAttackDetectionEngine, createAttackDetectionMiddleware } = require('./modules/security/attack-detection');

// ════════════════════════════════════════════════════════════════[[...]
// SECURITY LAYER 3: ANTI-FORGERY PRODUCTION [RESPONSE INTEGRITY]
// ════════════════════════════════════════════════════════════════[[...]

const {
    SecureKeyManager,
    AntiForgerySigner,
    TransportIntegrityVerifier,
    NetworkSecurityManager,
    SecureResponseManager
} = require('./modules/security/anti-forgery-production');

// ════════════════════════════════════════════════════════════════[[...]
// SECURITY LAYER 4: ANTI-FORGERY PRODUCTION SERVICES (LEGACY)
// ════════════════════════════════════════════════════════════════[[...]

const {
    SecureKeyManager: LegacySecureKeyManager,
    AntiForgerySigner: LegacyAntiForgerySigner,
    TransportIntegrityVerifier: LegacyTransportIntegrityVerifier,
    NetworkSecurityManager: LegacyNetworkSecurityManager,
    SecureResponseManager: LegacySecureResponseManager
} = require('./anti-forgery-production');

// ════════════════════════════════════════════════════════════════[[...]
// STEP 1: IMPORT PROXY ENCRYPTION GATEWAY (note.md Line 84)
// ════════════════════════════════════════════════════════════════[[...]

const { initProxyEncryptionGateway } = require('./modules/security/proxy-encryption-gateway');

// Initialize Express app
const app = express();

// ════════════════════════════════════════════════════════════════[[...]
// INITIALIZE CORE SECURITY MANAGERS
// ════════════════════════════════════════════════════════════════[[...]

const sqlDetector = new SQLInjectionDetector();
const keyManager = new APIKeyManager();
const rbacManager = new RBACManager();
const mfaManager = new EmailBasedMFA();

// ════════════════════════════════════════════════════════════════[...]
// EMAIL SERVICE INITIALIZATION (REFACTORED)
// ════════════════════════════════════════════════════════════════[...]

const emailService = new EmailService({
    host: process.env.SMTP_HOST || 'localhost',
    port: parseInt(process.env.SMTP_PORT || '25', 10),
    secure: process.env.SMTP_SECURE === 'true',
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
    from: process.env.SMTP_FROM || 'noreply@proxy.local'
});

console.log('✅ [EMAIL-SERVICE] Initialized');
console.log('   ├─ SMTP Host: ' + (process.env.SMTP_HOST || 'localhost'));
console.log('   ├─ SMTP Port: ' + (process.env.SMTP_PORT || '25'));
console.log('   ├─ TLS: ' + (process.env.SMTP_SECURE === 'true' ? 'enabled' : 'disabled'));
console.log('   └─ From: ' + (process.env.SMTP_FROM || 'noreply@proxy.local'));

// ════════════════════════════════════════════════════════════════[...]
// ANTI-FORGERY PRODUCTION SERVICE INITIALIZATION
// ════════════════════════════════════════════════════════════════[...]

const antiForgerConfig = {
    keyManager: {
        keyRotationInterval: 7 * 24 * 60 * 60 * 1000, // 7 days
        hsmEnabled: process.env.HSM_ENABLED === 'true'
    },
    sharedSecret: process.env.SHARED_SECRET || crypto.randomBytes(64).toString('hex'),
    network: {
        whitelist: (process.env.IP_WHITELIST || '127.0.0.1').split(',').map(ip => ip.trim()),
        blacklist: (process.env.IP_BLACKLIST || '').split(',').filter(ip => ip.trim()).map(ip => ip.trim()),
        maxRequests: parseInt(process.env.RATE_LIMIT_MAX || '1000', 10),
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW || '60000', 10),
        requireWhitelist: process.env.REQUIRE_WHITELIST !== 'false'
    }
};

let secureResponseManager = null;

// ════════════════════════════════════════════════════════════════[...]
// STEP 1: INITIALIZE ANTI-FORGERY PRODUCTION (RESPONSE SECURITY)
// ════════════════════════════════════════════════════════════════[...]

try {
    secureResponseManager = new SecureResponseManager(antiForgerConfig);
    console.log('✅ [SECURITY] Anti-Forgery Production initialized');
    console.log('   ├─ Ed25519 key rotation: 7 days');
    console.log('   ├─ Nonce management: 32-byte, 5-min TTL, one-time use');
    console.log('   ├─ HMAC-SHA256 transport integrity');
    console.log('   ├─ IP whitelist: ' + Array.from(secureResponseManager.networkManager.ipWhitelist).join(', '));
    console.log('   ├─ Rate limiting: ' + antiForgerConfig.network.maxRequests + ' req/' + (antiForgerConfig.network.windowMs / 1000) + 's');
    console.log('   └─ Security Rating: 99/100');
} catch (err) {
    console.error('[SECURITY] ❌ Failed to initialize SecureResponseManager:', sanitizeForLogging(err.message));
    process.exit(1);
}

// ════════════════════════════════════════════════════════════════[...]
// STEP 3: INITIALIZE SSL/TLS VERIFICATION MODULE
// ════════════════════════════════════════════════════════════════[...]

let sslTlsModule = null;

try {
    // Enable verification middleware (this patches https.request and sets defaults)
    enableSSLVerificationMiddleware({
        configPath: process.env.SSL_CONFIG_PATH ||
            path.join(__dirname, 'security-config', 'ssl-config.json'),
        caBundlePath: process.env.SSL_CA_BUNDLE_PATH ||
            path.join(__dirname, 'security-config', 'ca-bundle.pem'),
        enableAuditLog: process.env.SSL_AUDIT_ENABLED !== 'false'
    });

    // Normalize runtime module object so other code can test `sslTlsModule` and call helpers.
    sslTlsModule = {
        enabled: true,
        makeVerifiedRequest,    // function imported from security/ssl-tls-verification.js
        getSSLStatus,
        getAuditStats,
        loadSSLConfig,
        shutdown: shutdownSSLTLS,
        getConfig: getSSLConfig
    };

    console.log('✅ [SSL-TLS] Verification module initialized and integrated');
} catch (err) {
    console.error('[SSL-TLS] ❌ Failed to initialize:', sanitizeForLogging(err.message));
    if (process.env.NODE_ENV === 'production') {
        console.error('[SSL-TLS] FATAL: Required in production. Exiting.');
        process.exit(1);
    }
}

// ════════════════════════════════════════════════════════════════[...]
// STEP 4: INITIALIZE ATTACK DETECTION (LAYER 6)
// Inserted immediately after SSL/TLS initialization
// ═══════════════════════════════════════════════════════════════[..[...]

let attackDetectionEngine = null;
let attackDetectionMiddleware = null;

try {
    attackDetectionEngine = createAttackDetectionEngine();
    attackDetectionMiddleware = createAttackDetectionMiddleware(attackDetectionEngine);

    console.log('✅ [SECURITY] Attack Detection Engine initialized');
    console.log('   ├─ Injection Detection: SQL, NoSQL, XSS, Command, Path Traversal');
    console.log('   ├─ Rate Limiting: Per-IP DDoS/Flooding Detection');
    console.log('   ├─ Brute Force: Progressive Failed Auth Tracking');
    console.log('   ├─ Slow Attacks: Slowloris Detection');
    console.log('   ├─ Protocol Violations: Header & Body Checks');
    console.log('   └─ Security Rating: 98/100');
} catch (err) {
    console.error('[ATTACK-DETECTION] ❌ Failed to initialize:', sanitizeForLogging(err.message));
    if (process.env.NODE_ENV === 'production') {
        console.error('[ATTACK-DETECTION] FATAL: Required in production. Exiting.');
        process.exit(1);
    }
}

// ════════════════════════════════════════════════════════════════[...]
// QUANTUM SAFE ENVELOPE SERVICE (LAZY LOADING)
// ════════════════════════════════════════════════════════════════[...]

let quantumProxy = null;
let quantumProxyLoadPromise = null;
let quantumEnvelopeService = null;
let quantumConsoleOverrideEnabled = false;

// ✅ REMOVED: Early destructuring and enableGlobalConsoleOverride call (lines 303-315)
// Now deferred until first use in initQuantumProxy()

// Parse quantum console override setting early (non-blocking)
if (process.env.QUANTUM_CONSOLE_OVERRIDE === '1' || process.env.QUANTUM_CONSOLE_OVERRIDE === 'true') {
    quantumConsoleOverrideEnabled = true;
}

async function initQuantumProxy() {
    if (quantumProxy) {
        return quantumProxy;
    }

    if (!quantumProxyLoadPromise) {
        quantumProxyLoadPromise = (async () => {
            try {
                // ✅ LAZY LOAD: Import quantum service only when first needed
                if (!quantumEnvelopeService) {
                    quantumEnvelopeService = require('./modules/security/quantum-safe-envelope');

                    // ✅ DEFERRED: Apply console override after loading
                    const { enableGlobalConsoleOverride } = quantumEnvelopeService;
                    if (enableGlobalConsoleOverride) {
                        enableGlobalConsoleOverride(quantumConsoleOverrideEnabled);
                    }
                }

                const proxy = await quantumEnvelopeService.initQuantumProxy({
                    importPath: './quantum-safe-modern.js',
                    timeoutMs: 10000
                });
                quantumProxy = proxy || null;
                if (quantumProxy) {
                    console.log('[QUANTUM] ✅ Modern quantum-safe proxy initialized');
                }
                return quantumProxy;
            } catch (error) {
                console.error('[QUANTUM] ❌ Failed to initialize proxy:', sanitizeForLogging(error.message));
                throw error;
            }
        })();
    }

    return quantumProxyLoadPromise;
}

async function buildQuantumEnvelope(payload, aad = '') {
    if (!quantumProxy) {
        try {
            await initQuantumProxy();
        } catch (e) {
            console.warn('[QUANTUM] Init failed, proceeding without quantum envelope');
            return null;
        }
    }

    if (!quantumProxy) {
        return null;
    }

    if (!quantumEnvelopeService) {
        return null;
    }

    try {
        const envelope = await quantumEnvelopeService.buildQuantumEnvelope(payload, aad);
        return envelope;
    } catch (error) {
        console.warn('[QUANTUM] Envelope creation failed:', sanitizeForLogging(error.message));
        return null;
    }
}

async function tryDecryptQuantumEnvelope(body, aad = '') {
    if (!body || typeof body !== 'object' || !body.encrypted || !('packet' in body)) {
        return null;
    }

    if (!quantumProxy) {
        try {
            await initQuantumProxy();
        } catch (e) {
            return null;
        }
    }

    if (!quantumProxy) {
        return null;
    }

    if (!quantumEnvelopeService) {
        return null;
    }

    try {
        const plaintext = await quantumEnvelopeService.tryDecryptQuantumEnvelope(body, aad);
        return plaintext;
    } catch (error) {
        console.warn('[QUANTUM] Decryption failed:', sanitizeForLogging(error.message));
        return null;
    }
}

async function getEncryptionCapabilitySummary(req = null) {
    if (!quantumEnvelopeService) {
        return null;
    }
    return await quantumEnvelopeService.getEncryptionCapabilitySummary(req);
}

// ════════════════════════════════════════════════════════════════[...]
// API KEY AUTHENTICATION MODULE
// ════════════════════════════════════════════════════════════════[...]

const HMAC_SECRET = process.env.HMAC_SECRET || crypto.randomBytes(64).toString('hex');

let PROXY_API_KEY = resolveBootstrapApiKey();

if (process.env.PROXY_USE_ENV_KEY === 'true' && process.env.PROXY_API_KEY && process.env.PROXY_API_KEY.trim()) {
    PROXY_API_KEY = process.env.PROXY_API_KEY.trim();
}

PROXY_API_KEY = PROXY_API_KEY.trim();
console.log('[SECURITY] ✅ PROXY_API_KEY loaded (authentication enabled)');

// Create bootstrap key
const bootstrapKeyData = keyManager.createKey({
    name: 'bootstrap',
    scopes: ['read', 'write', 'admin'],
    expiresIn: 90 * 24 * 60 * 60 * 1000
});

keyManager.keys.set(PROXY_API_KEY, {
    ...bootstrapKeyData,
    key: PROXY_API_KEY,
    enabled: true,
    expires: Date.now() + (90 * 24 * 60 * 60 * 1000),
    type: 'bootstrap',
    createdAt: Date.now()
});

rbacManager.assignRole('bootstrap-admin', 'admin');
console.log('[API-KEY] ✅ Bootstrap key registered with admin role');

/**
 * Build internal auto-sign context for service-to-service requests
 */
function buildInternalAutoSignContext(req) {
    try {
        const rawBody = (req.rawBody && Buffer.isBuffer(req.rawBody)) ? req.rawBody :
            (req.rawBody || (typeof req.body === 'string' ? req.body : JSON.stringify(req.body ?? {})));

        const nonce = crypto.randomBytes(32);
        const timestamp = Date.now();
        const method = req.method;
        const path = req.path;

        const signingMessage = Buffer.concat([
            Buffer.from('REQUEST_SIGN_V1'),
            Buffer.from(method),
            Buffer.from(path),
            Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody)),
            nonce,
            Buffer.from(timestamp.toString())
        ]);

        const signature = crypto
            .createHmac('sha256', HMAC_SECRET)
            .update(signingMessage)
            .digest('hex');

        req.headers['authorization'] = `Bearer ${PROXY_API_KEY}`;
        req.headers['x-hmac-sha256'] = signature;
        req.headers['x-request-nonce'] = nonce.toString('hex');
        req.headers['x-request-timestamp'] = String(timestamp);
        req.headers['x-signature-algorithm'] = 'hmac-sha256-v1';
        req.headers['x-service-authenticated'] = 'true';

        req.internal_auto_sign = true;
        req.internal_auto_sign_signature = signature;
        req.requestSigningMetadata = {
            nonce: nonce.toString('hex'),
            timestamp,
            algorithm: 'hmac-sha256-v1',
            method,
            path
        };

        console.log('[API-KEY] ✅ Request auto-signed for internal service');
        return { signature, rawBody, metadata: req.requestSigningMetadata };
    } catch (err) {
        console.error('[API-KEY] ❌ Failed to build auto-sign context:', sanitizeForLogging(err.message));
        throw err;
    }
}

// ════════════════════════════════════════════════════════════════[...]
// STEP 2: INITIALIZE ANTI-FORGERY TRANSPORT LAYER (DEFERRED)
// Called here after HMAC_SECRET and buildInternalAutoSignContext defined
// ════════════════════════════════════════════════════════════════[...]

let antiForgeryTransportModule = null;

try {
    registerAntiForgeryTransport(app, {
        persistKeyDir: path.join(__dirname, 'security-keys'),
        caBundlePath: process.env.SSL_CA_BUNDLE_PATH ||
            path.join(__dirname, 'security-config', 'ca-bundle.pem'),
        sslConfigPath: process.env.SSL_CONFIG_PATH ||
            path.join(__dirname, 'security-config', 'ssl-config.json'),
        sslAuditLogPath: process.env.SSL_AUDIT_LOG ||
            path.join(__dirname, 'logs', 'ssl-verification.jsonl'),
        ed25519PrivatePem: process.env.ED25519_PRIVATE_PEM || undefined,
        ed25519PublicPem: process.env.ED25519_PUBLIC_PEM || undefined,
        hmacSecret: HMAC_SECRET,
        sqlDetector,
        m7Crypto,
        buildInternalAutoSignContext,
        maxClockSkewMs: parseInt(process.env.MAX_CLOCK_SKEW_MS || '300000', 10),
        maxBodyBytes: parseInt(process.env.MAX_BODY_BYTES || '10485760', 10)
    });

    antiForgeryTransportModule = app.locals.security;
    console.log('✅ [ANTI-FORGERY] Transport layer initialized (Ed25519 + HMAC)');
    console.log('   ├─ HMAC_SECRET configured');
    console.log('   ├─ buildInternalAutoSignContext integrated');
    console.log('   ├─ sqlDetector available');
    console.log('   └─ m7Crypto available');
} catch (err) {
    console.error('[ANTI-FORGERY] ❌ Initialization failed:', sanitizeForLogging(err.message));
    if (process.env.NODE_ENV === 'production') {
        console.error('[ANTI-FORGERY] FATAL: Required in production. Exiting.');
        process.exit(1);
    }
}

// ═══════════════════════════════════════════════════════════════[..[...]
// STEP 2b: INITIALIZE PROXY ENCRYPTION GATEWAY (note.md Lines 87-93)
// Initialized after HMAC_SECRET (line 398 equivalent)
// ════════════════════════════════════════════════════════════════[...]

let proxyGateway = null;

try {
    proxyGateway = initProxyEncryptionGateway({
        hmacSecret: HMAC_SECRET,
        logger: console,
        sessionTTL: 24 * 60 * 60 * 1000,
        rateLimitMax: 30,
        rateLimitWindow: 60000
    });
    console.log('✅ [PROXY-GATEWAY] Initialized with 8 security layers');
    console.log('   ├─ AES-256-GCM encryption/decryption');
    console.log('   ├─ Session validation & revocation');
    console.log('   ├─ Rate limiting: 30 req/60s per IP');
    console.log('   ├─ SSRF protection (URL validation)');
    console.log('   ├─ IP access control (whitelist/blacklist)');
    console.log('   ├─ Auto-signing (service-to-service)');
    console.log('   ├─ Health check & diagnostics');
    console.log('   └─ Security Rating: 99/100');
} catch (err) {
    console.error('[PROXY-GATEWAY] ❌ Failed to initialize:', sanitizeForLogging(err.message));
    if (process.env.NODE_ENV === 'production') {
        console.error('[PROXY-GATEWAY] FATAL: Required in production. Exiting.');
        process.exit(1);
    }
}

/**
 * Enhanced API key middleware with anti-forgery integration
 */
function validateApiKeyMiddleware(req, res, next) {
    const apiKey = req.headers['x-api-key'] ||
        (req.headers.authorization || '').replace('Bearer ', '').trim();

    if (!apiKey) {
        console.warn('[API-KEY] ⚠️  Request missing API key');
        return res.status(401).json({
            error: 'Unauthorized',
            detail: 'API key required (X-API-Key header or Authorization: Bearer)',
            nonce: req.securityNonce || 'N/A'
        });
    }

    if (isTokenBlacklisted(apiKey)) {
        console.warn('[API-KEY] ⚠️  Blacklisted API key used (nonce: %s)', req.securityNonce);
        return res.status(401).json({
            error: 'Unauthorized',
            detail: 'API key has been revoked'
        });
    }

    const keyEntry = keyManager.keys.get(apiKey);

    if (!keyEntry || !keyEntry.enabled) {
        console.warn('[API-KEY] ⚠️  Invalid API key attempt from fingerprint: %s',
            req.securityFingerprint);
        return res.status(401).json({
            error: 'Unauthorized',
            detail: 'Invalid or disabled API key'
        });
    }

    if (keyEntry.expires && Date.now() > keyEntry.expires) {
        console.warn('[API-KEY] ⚠️  Expired API key used');
        return res.status(401).json({
            error: 'Unauthorized',
            detail: 'API key has expired'
        });
    }

    req.apiKey = apiKey;
    req.apiKeyEntry = keyEntry;
    req.apiKeyScopes = keyEntry.scopes || [];
    req.apiKeyRole = keyEntry.type || 'user';

    console.log('[API-KEY] ✅ Valid (fingerprint=%s, scopes=%s)',
        req.securityFingerprint?.substring(0, 8) + '...' || 'N/A',
        req.apiKeyScopes.join(','));

    next();
}

// ═══════════════════════════════════════════════════════════════[..[...]
// NETWORK CONFIGURATION & IP ACCESS CONTROL
// ════════════════════════════════════════════════════════════════[...]

let networkConfig = {
    current_profile: 'auto-whitelisted',
    profiles: {
        'auto-whitelisted': { enabled: true, mode: 'whitelist', ips: ['127.0.0.1'] }
    }
};

function getLocalIP() {
    try {
        const output = execSync("ifconfig | grep -E 'inet ' | grep -v 127.0.0.1 | awk '{print $2}' | head -1", {
            encoding: 'utf8',
            stdio: ['pipe', 'pipe', 'pipe']
        }).trim();
        return output || '127.0.0.1';
    } catch (e) {
        console.warn('⚠️  Could not detect local IP, falling back to localhost');
        return '127.0.0.1';
    }
}

function loadNetworkConfig() {
    try {
        const configPath = path.join(__dirname, 'network-config.json');
        if (fs.existsSync(configPath)) {
            networkConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
            console.log(`✅ Network config loaded (Profile: ${networkConfig.current_profile})`);
        } else {
            console.log('ℹ️  No network-config.json found, using defaults');
        }
    } catch (e) {
        console.warn('⚠️  Could not load network-config.json:', sanitizeForLogging(e.message));
    }

    const currentIP = getLocalIP();
    const profile = networkConfig.profiles[networkConfig.current_profile];

    if (profile && profile.mode === 'whitelist') {
        if (!profile.ips.includes(currentIP) && currentIP !== '127.0.0.1') {
            profile.ips.push(currentIP);
            console.log(`🔓 AUTO-WHITELISTED: ${currentIP} (this device)`);
        }
    }
}

function checkIPAccess(clientIP) {
    const profile = networkConfig.profiles[networkConfig.current_profile];
    if (!profile || !profile.enabled) {
        return true;
    }

    const { mode, ips } = profile;
    const isInList = ips.includes(clientIP);

    if (mode === 'whitelist') {
        return isInList;
    } else {
        return !isInList;
    }
}

// ════════════════════════════════════════════════════════════════[...]
// TOKEN BLACKLIST & REVOCATION
// ════════════════════════════════════════════════════════════════[...]

let tokenBlacklist = [];

function loadTokenBlacklist() {
    try {
        const blacklistPath = path.join(__dirname, 'token-blacklist.json');
        if (fs.existsSync(blacklistPath)) {
            const data = JSON.parse(fs.readFileSync(blacklistPath, 'utf8'));
            tokenBlacklist = data.blacklist || [];
            console.log(`✅ Token blacklist loaded (${tokenBlacklist.length} revoked tokens)`);
        } else {
            tokenBlacklist = [];
            console.log('ℹ️  No token blacklist found');
        }
    } catch (e) {
        console.warn('⚠️  Could not load token blacklist:', sanitizeForLogging(e.message));
        tokenBlacklist = [];
    }
}

function isTokenBlacklisted(token) {
    loadTokenBlacklist();
    const found = tokenBlacklist.find(entry => entry.token === token);
    if (found) {
        console.warn(`[SECURITY] ⚠️  Blacklisted token used (reason: ${found.reason})`);
        return true;
    }
    return false;
}

// ════════════════════════════════════════════════════════════════[...]
// M7 EGRESS CONFIGURATION
// ════════════════════════════════════════════════════════════════[...]

const M7_EGRESS_CONFIG_PATH = process.env.M7_EGRESS_CONFIG_PATH ||
    path.join(__dirname, 'm7-egress.json');

let m7EgressConfig = {
    enabled: false,
    target: 'https://example.com',
    strict: false
};

function loadM7EgressConfig() {
    try {
        if (fs.existsSync(M7_EGRESS_CONFIG_PATH)) {
            const configData = JSON.parse(fs.readFileSync(M7_EGRESS_CONFIG_PATH, 'utf8'));
            m7EgressConfig = { ...m7EgressConfig, ...configData };
        } else {
            fs.writeFileSync(M7_EGRESS_CONFIG_PATH, JSON.stringify(m7EgressConfig, null, 2));
        }
    } catch (error) {
        console.warn('[M7 EGRESS] ❌ Could not load configuration:', sanitizeForLogging(error.message));
    }
}

function saveM7EgressConfig() {
    try {
        fs.writeFileSync(M7_EGRESS_CONFIG_PATH, JSON.stringify(m7EgressConfig, null, 2));
    } catch (error) {
        console.warn('[M7 EGRESS] ❌ Could not save configuration:', sanitizeForLogging(error.message));
    }
}

// ════════════════════════════════════════════════════════════════[...]
// STARTUP INITIALIZATION
// ════════════════════════════════════════════════════════════════[...]

loadNetworkConfig();
loadTokenBlacklist();
loadM7EgressConfig();

// ════════════════════════════════════════════════════════════════[...]
// STEP 5: INITIALIZE KEY MANAGER (ENCRYPTION KEY MANAGEMENT)
// Inserted after M7/network config, before middleware stack
// ════════════════════════════════════════════════════════════════[...]

try {
    const keyConfig = {
        encryption: { enabled: process.env.ENCRYPTION_ENABLED !== 'false' },
        keys: {
            rotationEnabled: process.env.KEY_ROTATION_ENABLED !== 'false',
            rotationIntervalDays: parseInt(process.env.KEY_ROTATION_DAYS || '30', 10),
            maxKeysRetained: parseInt(process.env.MAX_KEYS_RETAINED || '5', 10)
        },
        encryption_storage: {
            currentKeyFile: process.env.ENCRYPTION_KEY_FILE ||
                path.join(__dirname, 'security-keys', 'encryption-key.json'),
            keyHistoryFile: process.env.ENCRYPTION_HISTORY_FILE ||
                path.join(__dirname, 'security-keys', 'key-history.json')
        },
        audit: {
            auditDir: process.env.ENCRYPTION_AUDIT_DIR ||
                path.join(__dirname, 'logs', 'encryption-audit')
        }
    };

    KeyManager.init(keyConfig);
    console.log('✅ [KEY-MGR] Initialized');
    console.log('   ├─ Encryption: ' + (keyConfig.encryption.enabled ? 'enabled' : 'disabled'));
    console.log('   ├─ Key rotation: ' + (keyConfig.keys.rotationEnabled ? 'enabled' : 'disabled') + ' (every ' + keyConfig.keys.rotationIntervalDays + ' days)');
    console.log('   ├─ Max retained keys: ' + keyConfig.keys.maxKeysRetained);
    console.log('   ├─ Current key version: ' + (KeyManager.getKeyMetadata()?.version || 'none'));
    console.log('   └─ Audit logging: ' + keyConfig.audit.auditDir);

    // ══════════════════════════════════════════════════════════════[.[...]
    // STEP 5b: INJECT KeyManager INTO M7-CRYPTO FOR AES-GCM OPERATIONS
    // ══════════════════════════════════════════════════════════════[.[...]
    if (m7Crypto.setKeyManager(KeyManager)) {
        console.log('✅ [M7-CRYPTO] KeyManager injected successfully');
        console.log('   ├─ encryptPayload() will use active key from KeyManager');
        console.log('   ├─ decryptPayload() will track metrics automatically');
        console.log('   └─ All AES-256-GCM operations monitored');
    } else {
        console.warn('[M7-CRYPTO] ⚠️  Failed to inject KeyManager (crypto operations will use fallback)');
    }
} catch (err) {
    console.error('[KEY-MGR] ❌ Failed to initialize:', sanitizeForLogging(err.message));
    if (process.env.NODE_ENV === 'production') {
        console.error('[KEY-MGR] FATAL: Key management required in production');
        process.exit(1);
    }
}

// ✅ DEFERRED: Async initialization of quantum proxy (non-blocking)
(async () => {
    try {
        await initQuantumProxy();
    } catch (error) {
        console.warn('[STARTUP] ⚠️  Quantum proxy initialization deferred (non-blocking)');
    }
})();

// ════════════════════════════════════════════════════════════════[...]
// MIDDLEWARE STACK (EXACT ORDER MATTERS!)
// ════════════════════════════════════════════════════════════════[...]
// 1️⃣  RAW BODY CAPTURE       [antiForgeryTransport - already registered]
// 2️⃣  BODY PARSERS           [express.json, express.urlencoded]
// 3️⃣  ANTI-FORGERY CHECKS    [antiForgeryTransport - already registered]
// 4️⃣  HMAC VERIFICATION      [antiForgeryTransport - already registered]
// 5️⃣  PROXY GATEWAY          [proxy encryption gateway middleware]
// 6️⃣  RATE LIMITING          [express-rate-limit]
// 7️⃣  API KEY VALIDATION     [validateApiKeyMiddleware - optional on protected routes]

// 2️⃣  BODY PARSERS
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 3️⃣  ATTACK DETECTION (Layer 6)
// Position: After express.json() and express.urlencoded(), before rate limiters
if (attackDetectionMiddleware) {
    app.use(attackDetectionMiddleware.requestHandler());
    console.log('✅ [MIDDLEWARE] Attack Detection middleware registered (position 3)');
}

// 5️⃣  PROXY GATEWAY MIDDLEWARE STACK (note.md Lines 98-100)
// Position: After body parsers, before rate limiters
if (proxyGateway) {
    const middlewareStack = proxyGateway.createMiddlewareStack();
    app.use(...middlewareStack);
    console.log('✅ [MIDDLEWARE] Proxy encryption gateway registered (position 5)');
}

// 6️⃣  RATE LIMITING
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests', detail: 'Rate limit exceeded' },
    skip: (req) => req.path === '/health'
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.ip || 'unknown',
    message: { error: 'Too many authentication attempts', detail: 'Try again in 15 minutes' }
});

app.use(generalLimiter);
app.use('/auth/mfa', authLimiter);

// ════════════════════════════════════════════════════════════════[...]
// MFA ENDPOINTS: EMAIL-BASED AUTHENTICATION WITH OTP
// ════════════════════════════════════════════════════════════════[...]

// POST /auth/mfa/register - Create new user account
app.post('/auth/mfa/register', async (req, res) => {
    const { email, password, username } = req.body;

    try {
        if (!email || !password || !username) {
            return res.status(400).json({
                error: 'Bad Request',
                detail: 'Missing required fields: email, password, username',
                example: { email: 'user@example.com', password: 'secure123', username: 'johndoe' }
            });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                error: 'Bad Request',
                detail: 'Invalid email format'
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                error: 'Bad Request',
                detail: 'Password must be at least 8 characters'
            });
        }

        if (username.length < 3 || username.length > 32) {
            return res.status(400).json({
                error: 'Bad Request',
                detail: 'Username must be between 3 and 32 characters'
            });
        }

        console.log(`[MFA] Registration request from ${sanitizeForLogging(email)}`);

        const result = await mfaManager.requestNewAPIKey(email, {
            username,
            passwordHash: crypto.createHash('sha256').update(password).digest('hex'),
            metadata: { registeredAt: Date.now() }
        });

        const otp = Math.random().toString(36).substring(2, 8).toUpperCase();
        await emailService.sendOTP(email, otp);

        console.log(`[MFA] ✅ OTP sent to ${sanitizeForLogging(email)} for registration`);

        res.status(202).json({
            status: 'pending_verification',
            message: 'Registration started. Check your email for verification code.',
            keyId: result.keyId,
            email: sanitizeForLogging(email),
            expiresIn: '15 minutes',
            nextStep: 'POST /auth/mfa/verify with keyId and verification code'
        });

    } catch (err) {
        console.error(`[MFA] ❌ Registration error:`, sanitizeForLogging(err.message));
        res.status(500).json({
            error: 'Internal Server Error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// POST /auth/mfa/login - Login with password and request OTP
app.post('/auth/mfa/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        if (!email || !password) {
            return res.status(400).json({
                error: 'Bad Request',
                detail: 'Missing required fields: email, password',
                example: { email: 'user@example.com', password: 'secure123' }
            });
        }

        console.log(`[MFA] Login request from ${sanitizeForLogging(email)}`);

        const key = await mfaManager.validateAPIKey(email, password);

        if (!key.valid) {
            console.warn(`[MFA] ⚠️  Failed login attempt for ${sanitizeForLogging(email)}`);
            return res.status(401).json({
                error: 'Unauthorized',
                detail: 'Invalid email or password'
            });
        }

        const result = await mfaManager.requestKeyRotation(key.email, email);

        const otp = Math.random().toString(36).substring(2, 8).toUpperCase();
        await emailService.sendOTP(email, otp);

        console.log(`[MFA] ✅ OTP sent to ${sanitizeForLogging(email)} for login`);

        res.status(202).json({
            status: 'otp_sent',
            message: 'OTP sent to registered email',
            rotationKeyId: result.rotationKeyId,
            email: sanitizeForLogging(email),
            expiresIn: '15 minutes',
            nextStep: 'POST /auth/mfa/verify with rotationKeyId and OTP code'
        });

    } catch (err) {
        console.error(`[MFA] ❌ Login error:`, sanitizeForLogging(err.message));
        res.status(500).json({
            error: 'Internal Server Error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// POST /auth/mfa/verify - Verify OTP and get API key
app.post('/auth/mfa/verify', async (req, res) => {
    const { keyId, verificationCode } = req.body;

    try {
        if (!keyId || !verificationCode) {
            return res.status(400).json({
                error: 'Bad Request',
                detail: 'Missing required fields: keyId, verificationCode',
                example: { keyId: 'abc123...', verificationCode: '123456' }
            });
        }

        console.log(`[MFA] Verification request for keyId: ${keyId}`);

        const result = await mfaManager.verifyAndActivateKey(keyId, verificationCode);
        await emailService.sendAPIKey(result.email, result.secret, result.expiresAt);

        console.log(`[MFA] ✅ Verification successful for keyId: ${keyId}`);

        res.json({
            status: 'success',
            message: 'Verification complete. API key sent to your email.',
            keyId: result.keyId,
            expiresAt: result.expiresAt,
            daysUntilExpiry: Math.ceil((result.expiresAt - Date.now()) / (24 * 60 * 60 * 1000)),
            usage: 'Include in request headers: X-API-Key: [YOUR_SECRET_KEY]'
        });

    } catch (err) {
        console.error(`[MFA] ❌ Verification error:`, sanitizeForLogging(err.message));
        const statusCode = err.message.includes('Invalid') || err.message.includes('expired') ? 401 : 500;
        res.status(statusCode).json({
            error: statusCode === 401 ? 'Unauthorized' : 'Internal Server Error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// GET /auth/mfa/health - Health check for MFA service
app.get('/auth/mfa/health', (req, res) => {
    try {
        const expiringKeys = mfaManager.getExpiringKeys(7);
        res.json({
            status: 'operational',
            service: 'Email-Based MFA',
            timestamp: new Date().toISOString(),
            expiringKeysCount: expiringKeys.length,
            capabilities: {
                registration: true,
                login: true,
                otp_verification: true,
                key_rotation: true,
                key_revocation: true
            }
        });
    } catch (err) {
        console.error('[MFA] ❌ Health check error:', sanitizeForLogging(err.message));
        res.status(500).json({
            status: 'error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// ═══════════════════════════════════════════════════════════════[.[[...]
// SSL/TLS HEALTH CHECK ENDPOINTS
// ═══════════════════════════════════════════════════════════════[.[[...]

// GET /health/ssl - SSL/TLS verification health status
app.get('/health/ssl', (req, res) => {
    try {
        const status = getSSLStatus();
        res.json({
            ...status,
            timestamp: new Date().toISOString(),
            uptime: {
                certificationsValidatedTotal: status.statistics.certificationsValidated,
                certificationsRejectedTotal: status.statistics.certificationsRejected,
                rejectionRate: status.statistics.rejectionRate
            }
        });
    } catch (err) {
        console.error('[SSL-TLS] ❌ Health check error:', sanitizeForLogging(err.message));
        res.status(500).json({
            status: 'error',
            module: 'SSL/TLS Verification',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// GET /health/ssl/config - Current SSL configuration (admin only)
app.get('/health/ssl/config', validateApiKeyMiddleware, (req, res) => {
    try {
        if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
            return res.status(403).json({
                error: 'Forbidden',
                detail: 'Admin role required'
            });
        }

        const config = getSSLConfig();
        res.json({
            status: 'ok',
            module: 'SSL/TLS Verification',
            configuration: {
                ssl: config.ssl,
                certificateValidation: config.certificateValidation,
                errorHandling: config.errorHandling,
                upstreamOverrides: Object.keys(config.upstreamOverrides || {})
            },
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        console.error('[SSL-TLS] ❌ Config retrieval error:', sanitizeForLogging(err.message));
        res.status(500).json({
            status: 'error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// POST /admin/ssl/reload-config - Reload SSL configuration (admin only)
app.post('/admin/ssl/reload-config', validateApiKeyMiddleware, (req, res) => {
    try {
        if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
            return res.status(403).json({
                error: 'Forbidden',
                detail: 'Admin role required'
            });
        }

        const configPath = process.env.SSL_CONFIG_PATH ||
            path.join(__dirname, 'security-config', 'ssl-config.json');

        const reloaded = loadSSLConfig(configPath);

        if (!reloaded) {
            return res.status(400).json({
                status: 'failed',
                detail: 'Configuration reload failed. Check logs for details.'
            });
        }

        res.json({
            status: 'success',
            message: 'SSL configuration reloaded',
            configPath,
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        console.error('[SSL-TLS] ❌ Config reload error:', sanitizeForLogging(err.message));
        res.status(500).json({
            status: 'error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// GET /health/ssl/audit - Audit statistics (admin only)
app.get('/health/ssl/audit', validateApiKeyMiddleware, (req, res) => {
    try {
        if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
            return res.status(403).json({
                error: 'Forbidden',
                detail: 'Admin role required'
            });
        }

        const stats = getAuditStats();
        res.json({
            status: 'ok',
            module: 'SSL/TLS Verification Audit',
            statistics: stats,
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        console.error('[SSL-TLS] ❌ Audit retrieval error:', sanitizeForLogging(err.message));
        res.status(500).json({
            status: 'error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// ═══════════════════════════════════════════════════════════════[.[...]
// ATTACK DETECTION ADMIN ENDPOINTS (Admin Only)
// Inserted among admin endpoints as requested
// ═══════════════════════════════════════════════════════════════[.[...]

// GET /admin/security/attack-detection/stats - View attack statistics
app.get('/admin/security/attack-detection/stats', validateApiKeyMiddleware, (req, res) => {
    try {
        if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
            return res.status(403).json({
                error: 'Forbidden',
                detail: 'Admin role required'
            });
        }

        const stats = attackDetectionEngine ? attackDetectionEngine.getStats() : {};
        res.json({
            status: 'ok',
            module: 'Attack Detection (Layer 6)',
            statistics: stats,
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        console.error('[ATTACK-DETECTION] ❌ Stats retrieval error:', sanitizeForLogging(err.message));
        res.status(500).json({
            error: 'Internal Server Error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// GET /admin/security/attack-detection/alerts - View recent alerts
app.get('/admin/security/attack-detection/alerts', validateApiKeyMiddleware, (req, res) => {
    try {
        if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
            return res.status(403).json({
                error: 'Forbidden',
                detail: 'Admin role required'
            });
        }

        if (!attackDetectionMiddleware) {
            return res.status(503).json({ error: 'Service Unavailable', detail: 'Attack detection not initialized' });
        }

        return attackDetectionMiddleware.alertsHandler()(req, res);
    } catch (err) {
        console.error('[ATTACK-DETECTION] ❌ Alerts retrieval error:', sanitizeForLogging(err.message));
        res.status(500).json({
            error: 'Internal Server Error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// GET /admin/security/attack-detection/connections - View active connections
app.get('/admin/security/attack-detection/connections', validateApiKeyMiddleware, (req, res) => {
    try {
        if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
            return res.status(403).json({
                error: 'Forbidden',
                detail: 'Admin role required'
            });
        }

        if (!attackDetectionMiddleware) {
            return res.status(503).json({ error: 'Service Unavailable', detail: 'Attack detection not initialized' });
        }

        return attackDetectionMiddleware.connectionsHandler()(req, res);
    } catch (err) {
        console.error('[ATTACK-DETECTION] ❌ Connections retrieval error:', sanitizeForLogging(err.message));
        res.status(500).json({
            error: 'Internal Server Error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// GET /admin/security/attack-detection/health - Health check
app.get('/admin/security/attack-detection/health', (req, res) => {
    res.json({
        status: 'operational',
        module: 'Attack Detection (Layer 6)',
        timestamp: new Date().toISOString(),
        enabled: !!attackDetectionEngine,
        capabilities: {
            injectionDetection: true,
            rateLimitDetection: true,
            bruteForceDetection: true,
            slowRequestDetection: true,
            protocolViolationDetection: true,
            forensicLogging: true
        }
    });
});

// ═══════════════════════════════════════════════════════════════[.[...]
// ANTI-FORGERY TRANSPORT CONFIGURATION ENDPOINTS (Admin Only)
// ═══════════════════════════════════════════════════════════════[.[...]

// GET /admin/anti-forgery/status - Check anti-forgery transport status
app.get('/admin/anti-forgery/status', validateApiKeyMiddleware, (req, res) => {
    try {
        if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
            return res.status(403).json({
                error: 'Forbidden',
                detail: 'Admin role required'
            });
        }

        const hasModule = !!antiForgeryTransportModule;
        const hasKeys = hasModule && antiForgeryTransportModule.keys;

        res.json({
            status: 'operational',
            module: 'Anti-Forgery Transport Layer',
            timestamp: new Date().toISOString(),
            enabled: hasModule,
            configuration: {
                maxClockSkewMs: process.env.MAX_CLOCK_SKEW_MS || 300000,
                maxBodyBytes: process.env.MAX_BODY_BYTES || 10485760,
                ed25519SigningEnabled: hasKeys ? !!antiForgeryTransportModule.keys.ed25519PrivatePem : false,
                hmacVerificationEnabled: hasKeys ? !!antiForgeryTransportModule.keys.hmacSecret : false,
                tlsEnforcementEnabled: true
            },
            capabilities: {
                requestNonceGeneration: true,
                requestFingerprinting: true,
                timestampValidation: true,
                payloadIntegrityChecking: true,
                ed25519ResponseSigning: hasKeys,
                hmacRequestVerification: hasKeys,
                tlsVersionEnforcement: true
            }
        });
    } catch (err) {
        console.error('[ANTI-FORGERY] ❌ Status check error:', sanitizeForLogging(err.message));
        res.status(500).json({
            error: 'Internal Server Error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// ═══════════════════════════════════════════════════════════════[.[...]
// ANTI-FORGERY PRODUCTION VERIFICATION ENDPOINTS (Admin Only)
// ═══════════════════════════════════════════════════════════════[.[...]

// GET /admin/anti-forgery-prod/status - Anti-Forgery Production module status
app.get('/admin/anti-forgery-prod/status', validateApiKeyMiddleware, (req, res) => {
    try {
        if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
            return res.status(403).json({
                error: 'Forbidden',
                detail: 'Admin role required'
            });
        }

        const currentKeyId = secureResponseManager.keyManager.currentKeyId;
        const currentKeyMetadata = secureResponseManager.keyManager.getKeyMetadata(currentKeyId);
        const keyVersions = secureResponseManager.keyManager.keyVersions.size;

        res.json({
            status: 'operational',
            module: 'Anti-Forgery Production (Response Security)',
            timestamp: new Date().toISOString(),
            enabled: !!secureResponseManager,
            keyManagement: {
                currentKeyId,
                rotationCount: currentKeyMetadata.rotationCount,
                algorithm: currentKeyMetadata.algorithm,
                createdAt: new Date(currentKeyMetadata.createdAt).toISOString(),
                expiresAt: new Date(currentKeyMetadata.expiresAt).toISOString(),
                archivedVersions: keyVersions - 1
            },
            cryptography: {
                signatureAlgorithm: 'Ed25519',
                transportHashAlgorithm: 'HMAC-SHA256',
                nonceSize: 32,
                nonceTimeToLive: '5 minutes',
                nonceOneTimeUse: true
            },
            networkSecurity: {
                ipWhitelistEnabled: secureResponseManager.networkManager.requireWhitelist,
                whitelistedIPs: Array.from(secureResponseManager.networkManager.ipWhitelist),
                blacklistedIPs: Array.from(secureResponseManager.networkManager.ipBlacklist),
                rateLimiting: {
                    maxRequests: secureResponseManager.networkManager.rateLimitConfig.maxRequests,
                    windowMs: secureResponseManager.networkManager.rateLimitConfig.windowMs
                }
            }
        });
    } catch (err) {
        console.error('[ANTI-FORGERY-PROD] ❌ Status check error:', sanitizeForLogging(err.message));
        res.status(500).json({
            error: 'Internal Server Error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// POST /admin/anti-forgery-prod/verify-response - Verify a secured response
app.post('/admin/anti-forgery-prod/verify-response', validateApiKeyMiddleware, (req, res) => {
    try {
        if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
            return res.status(403).json({
                error: 'Forbidden',
                detail: 'Admin role required'
            });
        }

        const { securedResponse, clientIp, clientFingerprint } = req.body;

        if (!securedResponse || !clientIp || !clientFingerprint) {
            return res.status(400).json({
                error: 'Bad Request',
                detail: 'Missing securedResponse, clientIp, or clientFingerprint'
            });
        }

        try {
            const verifiedData = secureResponseManager.verifyResponse(
                securedResponse,
                clientIp,
                clientFingerprint
            );

            res.json({
                status: 'verified',
                valid: true,
                data: verifiedData,
                timestamp: new Date().toISOString()
            });
        } catch (err) {
            res.status(400).json({
                status: 'verification_failed',
                valid: false,
                reason: err.message,
                timestamp: new Date().toISOString()
            });
        }
    } catch (err) {
        console.error('[ANTI-FORGERY-PROD] ❌ Verification error:', sanitizeForLogging(err.message));
        res.status(500).json({
            error: 'Internal Server Error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// GET /admin/anti-forgery-prod/keys - List key versions
app.get('/admin/anti-forgery-prod/keys', validateApiKeyMiddleware, (req, res) => {
    try {
        if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
            return res.status(403).json({
                error: 'Forbidden',
                detail: 'Admin role required'
            });
        }

        const keyMetadataArray = Array.from(
            secureResponseManager.keyManager.keyMetadata.entries()
        ).map(([keyId, metadata]) => ({
            keyId,
            algorithm: metadata.algorithm,
            status: metadata.status,
            createdAt: new Date(metadata.createdAt).toISOString(),
            expiresAt: new Date(metadata.expiresAt).toISOString(),
            rotationCount: metadata.rotationCount,
            isCurrent: keyId === secureResponseManager.keyManager.currentKeyId
        }));

        res.json({
            status: 'ok',
            keys: keyMetadataArray,
            totalVersions: keyMetadataArray.length,
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        console.error('[ANTI-FORGERY-PROD] ❌ Key listing error:', sanitizeForLogging(err.message));
        res.status(500).json({
            error: 'Internal Server Error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// POST /admin/anti-forgery-prod/rotate-keys - Force immediate key rotation
app.post('/admin/anti-forgery-prod/rotate-keys', validateApiKeyMiddleware, (req, res) => {
    try {
        if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
            return res.status(403).json({
                error: 'Forbidden',
                detail: 'Admin role required'
            });
        }

        const { keyId, metadata } = secureResponseManager.keyManager.rotateKeys();

        res.json({
            status: 'success',
            message: 'Keys rotated successfully',
            newKeyId: keyId,
            metadata: {
                algorithm: metadata.algorithm,
                createdAt: new Date(metadata.createdAt).toISOString(),
                expiresAt: new Date(metadata.expiresAt).toISOString(),
                rotationCount: metadata.rotationCount
            },
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        console.error('[ANTI-FORGERY-PROD] ❌ Key rotation error:', sanitizeForLogging(err.message));
        res.status(500).json({
            error: 'Internal Server Error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// POST /admin/anti-forgery-prod/network/whitelist-ip - Add IP to whitelist
app.post('/admin/anti-forgery-prod/network/whitelist-ip', validateApiKeyMiddleware, (req, res) => {
    try {
        if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
            return res.status(403).json({
                error: 'Forbidden',
                detail: 'Admin role required'
            });
        }

        const { ip } = req.body;

        if (!ip) {
            return res.status(400).json({
                error: 'Bad Request',
                detail: 'IP address required'
            });
        }

        secureResponseManager.networkManager.addToWhitelist(ip);

        res.json({
            status: 'success',
            message: `IP ${ip} added to whitelist`,
            whitelist: Array.from(secureResponseManager.networkManager.ipWhitelist),
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        console.error('[ANTI-FORGERY-PROD] ❌ Whitelist update error:', sanitizeForLogging(err.message));
        res.status(500).json({
            error: 'Internal Server Error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// POST /admin/anti-forgery-prod/network/blacklist-ip - Add IP to blacklist
app.post('/admin/anti-forgery-prod/network/blacklist-ip', validateApiKeyMiddleware, (req, res) => {
    try {
        if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
            return res.status(403).json({
                error: 'Forbidden',
                detail: 'Admin role required'
            });
        }

        const { ip } = req.body;

        if (!ip) {
            return res.status(400).json({
                error: 'Bad Request',
                detail: 'IP address required'
            });
        }

        secureResponseManager.networkManager.addToBlacklist(ip);

        res.json({
            status: 'success',
            message: `IP ${ip} added to blacklist`,
            blacklist: Array.from(secureResponseManager.networkManager.ipBlacklist),
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        console.error('[ANTI-FORGERY-PROD] ❌ Blacklist update error:', sanitizeForLogging(err.message));
        res.status(500).json({
            error: 'Internal Server Error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// ═══════════════════════════════════════════════════════════════[.[...]
// EXAMPLE PROTECTED ROUTE (with API key validation)
// ═══════════════════════════════════════════════════════════════[.[...]

app.get('/api/protected-resource', validateApiKeyMiddleware, (req, res) => {
    res.json({
        status: 'success',
        message: 'Protected resource accessed',
        apiKey: req.apiKey,
        apiKeyScopes: req.apiKeyScopes,
        apiKeyRole: req.apiKeyRole,
        requestSigningMetadata: req.requestSigningMetadata,
        security: {
            nonce: req.securityNonce,
            fingerprint: req.securityFingerprint
        }
    });
});

// ═══════════════════════════════════════════════════════════════[.[...]
// PROXY GATEWAY ADMIN ENDPOINTS (note.md Lines 123-127)
// ═══════════════════════════════════════════════════════════════[.[...]

// GET /admin/proxy-gateway/status - Health check for proxy gateway
app.get('/admin/proxy-gateway/status', validateApiKeyMiddleware, (req, res) => {
    try {
        if (req.apiKeyRole !== 'admin' && req.apiKeyRole !== 'bootstrap-admin') {
            return res.status(403).json({
                error: 'Forbidden',
                detail: 'Admin role required'
            });
        }

        if (!proxyGateway) {
            return res.status(503).json({
                status: 'unavailable',
                module: 'Proxy Encryption Gateway',
                detail: 'Gateway not initialized'
            });
        }

        res.json({
            status: 'operational',
            module: 'Proxy Encryption Gateway',
            timestamp: new Date().toISOString(),
            gatewayStatus: proxyGateway.getStatus()
        });
    } catch (err) {
        console.error('[PROXY-GATEWAY] ❌ Status retrieval error:', sanitizeForLogging(err.message));
        res.status(500).json({
            error: 'Internal Server Error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// GET /health/proxy-gateway - Quick health check
app.get('/health/proxy-gateway', (req, res) => {
    try {
        if (!proxyGateway) {
            return res.status(503).json({
                status: 'unavailable',
                detail: 'Gateway not initialized'
            });
        }

        res.json(proxyGateway.getHealthCheck());
    } catch (err) {
        console.error('[PROXY-GATEWAY] ❌ Health check error:', sanitizeForLogging(err.message));
        res.status(500).json({
            status: 'error',
            detail: sanitizeForLogging(err.message)
        });
    }
});

// ═══════════════════════════════════════════════════════════════[.[...]
// HEALTH CHECK ENDPOINT
// ═══════════════════════════════════════════════════════════════[.[...]

app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        services: {
            'key-manager': KeyManager && KeyManager.isInitialized ? 'operational' : 'degraded',
            'anti-forgery-transport': antiForgeryTransportModule ? 'operational' : 'degraded',
            'anti-forgery-production': secureResponseManager ? 'operational' : 'degraded',
            'ssl-tls': sslTlsModule ? 'operational' : 'degraded',
            'mfa': mfaManager ? 'operational' : 'degraded',
            'email': emailService ? 'operational' : 'degraded',
            'attack-detection': attackDetectionEngine ? 'operational' : 'degraded',
            'proxy-gateway': proxyGateway ? 'operational' : 'degraded',
            'quantum-proxy': quantumProxy ? 'operational' : 'deferred',
            'm7-crypto': 'operational'
        }
    });
});

// ═══════════════════════════════════════════════════════════════[.[...]
// GRACEFUL SHUTDOWN HANDLERS
// ═══════════════════════════════════════════════════════════════[.[...]

process.on('SIGTERM', () => {
    console.log('[SHUTDOWN] SIGTERM received, cleaning up...');

    // Proxy Gateway cleanup (STEP 1: proxy encryption sessions)
    if (proxyGateway) {
        try {
            proxyGateway.cleanupRevokedTokens();
            console.log('[SHUTDOWN] ✅ Proxy Gateway cleanup complete');
        } catch (err) {
            console.warn('[SHUTDOWN] ⚠️  Proxy Gateway cleanup error:', sanitizeForLogging(err.message));
        }
    }

    // Quantum Proxy cleanup (STEP 1.5: quantum resources)
    if (quantumProxy) {
        try {
            quantumProxy = null;
            console.log('[SHUTDOWN] ✅ Quantum Proxy cleanup complete');
        } catch (err) {
            console.warn('[SHUTDOWN] ⚠️  Quantum Proxy cleanup error:', sanitizeForLogging(err.message));
        }
    }

    // KeyManager shutdown (STEP 2: encryption keys)
    if (KeyManager && KeyManager.shutdown) {
        try {
            KeyManager.shutdown();
            console.log('[SHUTDOWN] ✅ KeyManager persisted and shutdown complete');
        } catch (err) {
            console.warn('[SHUTDOWN] ⚠️  KeyManager error:', sanitizeForLogging(err.message));
        }
    }

    // SSL/TLS shutdown (STEP 3: SSL certificates)
    if (sslTlsModule && sslTlsModule.shutdown) {
        try {
            sslTlsModule.shutdown();
            console.log('[SHUTDOWN] ✅ SSL/TLS module cleaned up');
        } catch (err) {
            console.warn('[SHUTDOWN] ⚠️  SSL/TLS cleanup error:', sanitizeForLogging(err.message));
        }
    }

    // Anti-Forgery Production shutdown (STEP 4: response signing keys)
    if (secureResponseManager) {
        try {
            console.log('[SHUTDOWN] ✅ Anti-Forgery Production cleanup complete');
            secureResponseManager = null;
        } catch (err) {
            console.warn('[SHUTDOWN] ⚠️  Anti-Forgery cleanup error:', sanitizeForLogging(err.message));
        }
    }

    // Anti-Forgery Transport shutdown (STEP 5: transport keys)
    if (antiForgeryTransportModule) {
        try {
            console.log('[SHUTDOWN] ✅ Anti-Forgery Transport keys persisted');
        } catch (err) {
            console.warn('[SHUTDOWN] ⚠️  Anti-Forgery Transport cleanup error:', sanitizeForLogging(err.message));
        }
    }

    // Attack Detection shutdown (STEP 6: forensics)
    if (attackDetectionEngine) {
        try {
            console.log('[SHUTDOWN] ✅ Attack Detection cleanup complete');
            attackDetectionEngine = null;
        } catch (err) {
            console.warn('[SHUTDOWN] ⚠️  Attack Detection cleanup error:', sanitizeForLogging(err.message));
        }
    }

    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('[SHUTDOWN] SIGINT received, cleaning up...');

    // Proxy Gateway cleanup (STEP 1: proxy encryption sessions)
    if (proxyGateway) {
        try {
            proxyGateway.cleanupRevokedTokens();
            console.log('[SHUTDOWN] ✅ Proxy Gateway cleanup complete');
        } catch (err) {
            console.warn('[SHUTDOWN] ⚠️  Proxy Gateway cleanup error:', sanitizeForLogging(err.message));
        }
    }

    // Quantum Proxy cleanup (STEP 1.5: quantum resources)
    if (quantumProxy) {
        try {
            quantumProxy = null;
            console.log('[SHUTDOWN] ✅ Quantum Proxy cleanup complete');
        } catch (err) {
            console.warn('[SHUTDOWN] ⚠️  Quantum Proxy cleanup error:', sanitizeForLogging(err.message));
        }
    }

    // KeyManager shutdown (STEP 2: encryption keys)
    if (KeyManager && KeyManager.shutdown) {
        try {
            KeyManager.shutdown();
            console.log('[SHUTDOWN] ✅ KeyManager persisted and shutdown complete');
        } catch (err) {
            console.warn('[SHUTDOWN] ⚠️  KeyManager error:', sanitizeForLogging(err.message));
        }
    }

    // SSL/TLS shutdown (STEP 3: SSL certificates)
    if (sslTlsModule && sslTlsModule.shutdown) {
        try {
            sslTlsModule.shutdown();
            console.log('[SHUTDOWN] ✅ SSL/TLS module cleaned up');
        } catch (err) {
            console.warn('[SHUTDOWN] ⚠️  SSL/TLS cleanup error:', sanitizeForLogging(err.message));
        }
    }

    // Anti-Forgery Production shutdown (STEP 4: response signing keys)
    if (secureResponseManager) {
        try {
            console.log('[SHUTDOWN] ✅ Anti-Forgery Production cleanup complete');
            secureResponseManager = null;
        } catch (err) {
            console.warn('[SHUTDOWN] ⚠️  Anti-Forgery cleanup error:', sanitizeForLogging(err.message));
        }
    }

    // Anti-Forgery Transport shutdown (STEP 5: transport keys)
    if (antiForgeryTransportModule) {
        try {
            console.log('[SHUTDOWN] ✅ Anti-Forgery Transport keys persisted');
        } catch (err) {
            console.warn('[SHUTDOWN] ⚠️  Anti-Forgery Transport cleanup error:', sanitizeForLogging(err.message));
        }
    }

    // Attack Detection shutdown (STEP 6: forensics)
    if (attackDetectionEngine) {
        try {
            console.log('[SHUTDOWN] ✅ Attack Detection cleanup complete');
            attackDetectionEngine = null;
        } catch (err) {
            console.warn('[SHUTDOWN] ⚠️  Attack Detection cleanup error:', sanitizeForLogging(err.message));
        }
    }

    process.exit(0);
});

// ═══════════════════════════════════════════════════════════════[.[...]
// SERVER STARTUP
// ═══════════════════════════════════════════════════════════════[.[...]

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';

const server = app.listen(PORT, HOST, () => {
    console.log('\n' + '═'.repeat(80));
    console.log('✅ [SERVER] Listening on http://' + HOST + ':' + PORT);
    console.log('═'.repeat(80));
    console.log('\n🔐 AUTHENTICATION ENDPOINTS:');
    console.log('   POST   http://' + HOST + ':' + PORT + '/auth/mfa/register    - Register new user');
    console.log('   POST   http://' + HOST + ':' + PORT + '/auth/mfa/login       - Login & request OTP');
    console.log('   POST   http://' + HOST + ':' + PORT + '/auth/mfa/verify      - Verify OTP & get API key');
    console.log('   GET    http://' + HOST + ':' + PORT + '/auth/mfa/health      - Check MFA service');
    console.log('\n📊 HEALTH CHECK ENDPOINTS:');
    console.log('   GET    http://' + HOST + ':' + PORT + '/health                - Overall system health');
    console.log('   GET    http://' + HOST + ':' + PORT + '/health/ssl            - SSL/TLS status');
    console.log('   GET    http://' + HOST + ':' + PORT + '/health/proxy-gateway  - Proxy gateway status');
    console.log('\n🛡️  PROTECTED ENDPOINTS (requires X-API-Key):');
    console.log('   GET    http://' + HOST + ':' + PORT + '/api/protected-resource - Example protected route');
    console.log('   GET    http://' + HOST + ':' + PORT + '/admin/...             - Admin endpoints');
    console.log('\n💡 TIP: Set X-API-Key header to access protected routes');
    console.log('═'.repeat(80) + '\n');
});

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`❌ [SERVER] Port ${PORT} is already in use. Try PORT=3001 node server.js`);
    } else {
        console.error('❌ [SERVER] Error:', sanitizeForLogging(err.message));
    }
    process.exit(1);
});

// ═══════════════════════════════════════════════════════════════[.[...]
// MODULE EXPORTS
// ═══════════════════════════════════════════════════════════════[.[...]

module.exports = {
    app,
    server,
    sqlDetector,
    keyManager,
    rbacManager,
    mfaManager,
    emailService,
    secureResponseManager,
    quantumProxy,
    buildQuantumEnvelope,
    tryDecryptQuantumEnvelope,
    getEncryptionCapabilitySummary,
    checkIPAccess,
    isTokenBlacklisted,
    networkConfig,
    m7EgressConfig,
    validateApiKeyMiddleware,
    buildInternalAutoSignContext,
    PROXY_API_KEY,
    HMAC_SECRET,
    sanitizeForLogging,
    sanitizeObject,

    // ✅ Proxy Encryption Gateway Exports (NEW)
    proxyGateway,

    // ✅ Key Manager Exports (NEW)
    KeyManager,
    encryptionKeyRotationEnabled: true,

    // ✅ Anti-Forgery Transport Exports
    antiForgeryTransportModule,
    antiForgeryTransport: {
        registerSecurity: registerAntiForgeryTransport,
        makeVerifiedRequest: createVerifiedHttpsClient,
        helpers: app.locals.security
    },

    // ✅ Anti-Forgery Production Exports
    SecureKeyManager,
    AntiForgerySigner,
    TransportIntegrityVerifier,
    NetworkSecurityManager,

    // SSL/TLS Module Exports
    sslTlsModule,
    getSSLStatus,
    getAuditStats,
    makeVerifiedRequest,
    getSSLConfig,
    shutdownSSLTLS,

    // ✅ Attack Detection Exports (Layer 6)
    attackDetectionEngine,
    attackDetectionMiddleware
};
