import { type Request, type Response, type NextFunction } from 'express'
const security = require('../lib/insecurity')

export function ensureFullAuth (req: Request, res: Response, next: NextFunction) {
  security.isAuthorized()(req, res, () => {
    const authType = (req.auth && (req.auth as any).authType) || (req.user && (req.user as any).authType)
    if (authType === 'password_valid_needs_second_factor_token' || authType === '2fa_temp') {
      return res.status(401).json({ error: 'Full authentication required' })
    }
    next()
  })
}
