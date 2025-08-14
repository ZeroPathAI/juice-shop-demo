/* Rate limiting */
function verifyResetRequest(req, res, next) {
  const { email, resetToken } = req.body;
  if (!email || !resetToken) {
    return res.status(400).json({ error: 'Missing email or reset token' });
  }
  // Placeholder for token validation and user verification
  next();
}
  app.enable('trust proxy')
  app.use('/rest/user/reset-password',
    new RateLimit({
      windowMs: 5 * 60 * 1000,
      max: 100,
      keyGenerator ({ headers, ip }) { return headers['Forwarded'] ?? ip }
    }),
    verifyResetRequest)
