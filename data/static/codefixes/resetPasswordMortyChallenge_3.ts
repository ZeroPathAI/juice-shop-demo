/* Rate limiting */
  app.enable('trust proxy')
  app.use('/rest/user/reset-password', new RateLimit({
    windowMs: 3 * 60 * 1000,
    max: 10,
    keyGenerator ({ headers, ip }) { return headers['X-Forwarded-For'] ?? ip }
  }))

  // Security: validate reset tokens and prevent enumeration
  app.use('/rest/user/reset-password', (req, res, next) => {
    const token = req.body.token || req.query.token;
    if (!token || typeof token !== 'string' || !/^[A-Za-z0-9\-_]+$/.test(token)) {
      res.cookie('resetToken', 'invalid', { httpOnly: true, sameSite: 'Strict' });
      return res.status(400).json({ message: 'Invalid request' });
    }
    next();
  });
