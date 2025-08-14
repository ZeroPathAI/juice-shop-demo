import { verifyCaptcha } from '../middleware/verifyCaptcha';
/* Rate limiting */
  app.enable('trust proxy')
  app.use('/rest/user/reset-password', verifyCaptcha, new RateLimit({
    windowMs: 5 * 60 * 1000,
    max: 100,
  }))
