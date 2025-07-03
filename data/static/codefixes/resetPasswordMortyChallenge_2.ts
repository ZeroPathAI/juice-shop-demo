/* Rate limiting */
  app.enable('trust proxy')
  app.use('/rest/user/reset-password', new RateLimit({
    windowMs: 5 * 60 * 1000,
    max: 100,
    keyGenerator ({ headers, ip }) {
      const forwardedFor = headers['x-forwarded-for'];
      if (forwardedFor) {
        return forwardedFor.split(',')[0].trim();
      }
      return ip;
    }
  }))
