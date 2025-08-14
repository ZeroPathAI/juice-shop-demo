import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { verifyCaptcha, getUserByEmail, recordFailedAttempt, resetFailedAttempts, verifySecurityAnswer, updatePasswordAndClearToken, sendResetNotification } from '../services/userSecurityService';
import { isValidPassword } from '../utils/passwordUtils';
import delay from '../utils/delay';
import { MAX_FAILED_ATTEMPTS, LOCKOUT_DURATION } from '../config/securityConfig';

/* Enhanced rate limiting & reset-password validation */
async function verifyResetRequest(req: Request, res: Response, next: NextFunction) {
  try {
    const { email, resetToken, newPassword, captchaToken, securityAnswer } = req.body;
    // Basic field validation
    if (!email || !resetToken || !newPassword || !captchaToken || !securityAnswer) {
      return res.status(400).json({ error: 'Invalid request parameters' });
    }
    // CAPTCHA verification
    if (!(await verifyCaptcha(captchaToken))) {
      return res.status(400).json({ error: 'CAPTCHA verification failed' });
    }
    // Prevent username enumeration
    const user = await getUserByEmail(email);
    await delay(500);
    if (!user) {
      return res
        .status(200)
        .json({ message: 'If your request is valid, you will receive a notification email.' });
    }
    // Account lockout check
    if (
      user.failedAttempts >= MAX_FAILED_ATTEMPTS &&
      Date.now() - user.lastFailedAt < LOCKOUT_DURATION
    ) {
      return res
        .status(429)
        .json({ error: 'Account is temporarily locked due to repeated failures' });
    }
    // Token validation and expiration
    if (user.resetToken !== resetToken || Date.now() > user.resetTokenExpires) {
      await recordFailedAttempt(user.id);
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    // Security question validation
    if (!(await verifySecurityAnswer(user.id, securityAnswer))) {
      await recordFailedAttempt(user.id);
      return res.status(400).json({ error: 'Security question validation failed' });
    }
    // Secure password validation
    if (!isValidPassword(newPassword)) {
      return res
        .status(400)
        .json({ error: 'New password does not meet security requirements' });
    }
    // Hash password
    const salt = crypto.randomBytes(16).toString('hex');
    const hashedPassword = crypto.scryptSync(newPassword, salt, 64).toString('hex');
    // Update password and clear token
    await updatePasswordAndClearToken(user.id, `${salt}:${hashedPassword}`);
    // Reset failed attempts
    await resetFailedAttempts(user.id);
    // Post-reset notification
    await sendResetNotification(email);
    // Proceed to next middleware
    next();
  } catch (err) {
    next(err);
  }
}
  app.enable('trust proxy')
  app.use('/rest/user/reset-password',
    new RateLimit({
      windowMs: 5 * 60 * 1000,
      max: 100,
      keyGenerator ({ headers, ip }) { return headers['Forwarded'] ?? ip }
    }),
    verifyResetRequest)
