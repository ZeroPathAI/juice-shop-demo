/* Rate limiting */
  app.use('/rest/user/reset-password',
    (req, res, next) => {
      if (!req.body.captchaToken) {
        return res.status(400).json({ error: 'CAPTCHA token missing' });
      }
      next();
    },
    new RateLimit({
      windowMs: 5 * 60 * 1000,
      max: 100,
      keyGenerator ({ headers, ip }) { return headers['X-Forwarded-For'] ?? ip }
    })
  );
