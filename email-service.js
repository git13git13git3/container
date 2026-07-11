/**
 * Enhanced Email Service Utilities
 * 
 * Provides email sending capabilities with nodemailer integration.
 * Used alongside EmailBasedMFA for OTP, API keys, and test emails.
 */

const nodemailer = require('nodemailer');

class EmailService {
    constructor(smtpConfig = {}) {
        this.smtpConfig = {
            host: smtpConfig.host || process.env.SMTP_HOST || 'localhost',
            port: parseInt(smtpConfig.port || process.env.SMTP_PORT || '25', 10),
            secure: smtpConfig.secure === true || smtpConfig.secure === 'true',
            auth: smtpConfig.user ? {
                user: smtpConfig.user || process.env.SMTP_USER,
                pass: smtpConfig.pass || process.env.SMTP_PASS
            } : undefined
        };

        this.fromEmail = smtpConfig.from || process.env.SMTP_FROM || 'noreply@proxy.local';
        this.transporter = this._initializeTransport();
    }

    _initializeTransport() {
        try {
            return nodemailer.createTransport(this.smtpConfig);
        } catch (err) {
            console.warn('[EmailService] Failed to initialize mail transport:', err.message);
            return null;
        }
    }

    /**
     * Send OTP verification code
     */
    async sendOTP(email, otp, options = {}) {
        if (!this.transporter) {
            throw new Error('Mail transporter not available');
        }

        try {
            const verifyUrl = options.verifyUrl
                ? `<p><a href="${options.verifyUrl}" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block;">Open verification link</a></p>`
                : '';

            const html = `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2>M7 Proxy Verification</h2>
                    <p>Your one-time verification code is:</p>
                    <h1 style="font-family: monospace; font-size: 32px; letter-spacing: 5px; background: #f4f4f4; padding: 20px; text-align: center; border-radius: 4px;">${otp}</h1>
                    <p>This code expires in 15 minutes.</p>
                    ${verifyUrl}
                    <p style="color: #666; font-size: 12px;">If you didn't request this, please ignore this email.</p>
                </div>
            `;

            const result = await this.transporter.sendMail({
                from: this.fromEmail,
                to: email,
                subject: 'Your M7 Proxy Verification Code',
                html
            });

            console.log(`[EMAIL] OTP sent to ${email} (messageId: ${result.messageId})`);
            return { success: true, messageId: result.messageId };
        } catch (err) {
            console.error(`[EMAIL] Failed to send OTP to ${email}:`, err.message);
            throw err;
        }
    }

    /**
     * Send API Key with secure display
     */
    async sendAPIKey(email, apiKey, expiresIn, options = {}) {
        if (!this.transporter) {
            throw new Error('Mail transporter not available');
        }

        try {
            const accessToken = options.accessToken
                ? `<p><strong>Access token:</strong> <code style="background: #f4f4f4; padding: 2px 6px; border-radius: 3px;">${options.accessToken}</code></p>`
                : '';

            const logoutUrl = options.logoutUrl
                ? `<p><a href="${options.logoutUrl}" style="color: #d00;">Revoke access now</a></p>`
                : '';

            const html = `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2>M7 Proxy API Key</h2>
                    <p>Your new API key has been generated:</p>
                    <p style="font-family: monospace; background: #f4f4f4; padding: 12px; word-break: break-all; border-radius: 4px; border-left: 4px solid #007bff;">${apiKey}</p>
                    <p><strong>Expires in:</strong> ${expiresIn}</p>
                    ${accessToken}
                    ${logoutUrl}
                    <p style="color: #d00; font-weight: bold;"><strong>⚠️ Save this key securely. You won't be able to see it again.</strong></p>
                    <p>Use this key in your API requests:</p>
                    <p style="font-family: monospace; background: #f4f4f4; padding: 12px; border-radius: 4px;">X-API-Key: ${apiKey}</p>
                </div>
            `;

            const result = await this.transporter.sendMail({
                from: this.fromEmail,
                to: email,
                subject: 'Your M7 Proxy API Key',
                html
            });

            console.log(`[EMAIL] API key sent to ${email} (messageId: ${result.messageId})`);
            return { success: true, messageId: result.messageId };
        } catch (err) {
            console.error(`[EMAIL] Failed to send API key to ${email}:`, err.message);
            throw err;
        }
    }

    /**
     * Send SMTP test email (for configuration validation)
     */
    async sendTestEmail({ host, port, secure, user, pass, from, to }) {
        const testTransport = nodemailer.createTransport({
            host,
            port: Number(port),
            secure: secure === true || secure === 'true',
            auth: user ? { user, pass } : undefined
        });

        try {
            const result = await testTransport.sendMail({
                from: from || process.env.SMTP_FROM || 'noreply@proxy.local',
                to,
                subject: 'LAN Proxy SMTP Test',
                text: 'LAN Proxy registration flow SMTP test succeeded.',
                html: `
                    <div style="font-family: Arial, sans-serif;">
                        <h2>SMTP Test Successful</h2>
                        <p>Your LAN Proxy email configuration is working correctly.</p>
                        <p><strong>Timestamp:</strong> ${new Date().toISOString()}</p>
                    </div>
                `
            });
            console.log(`[EMAIL] Test email delivered to ${to} (messageId: ${result.messageId})`);
            return { success: true, messageId: result.messageId };
        } catch (err) {
            console.error(`[EMAIL] Test email failed:`, err.message);
            throw err;
        } finally {
            await testTransport.close();
        }
    }
}

module.exports = EmailService;
