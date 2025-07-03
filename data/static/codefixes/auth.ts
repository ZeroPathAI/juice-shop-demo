import { Request, Response } from 'express'

// Authentication and Authorization middleware for finale resources

export function requireAuth(req: Request, res: Response, context: any) {
  // Simple authentication check: require Authorization header
  if (!req.headers.authorization) {
    res.status(401).send({ error: 'Unauthorized' })
    return context.error(new Error('Unauthorized'))
  }
  // TODO: validate token and set context.user
  return context.continue
}

export function requireAdmin(req: Request, res: Response, context: any) {
  const user = context.user
  if (!user || !user.isAdmin) {
    res.status(403).send({ error: 'Forbidden' })
    return context.error(new Error('Forbidden'))
  }
  return context.continue
}
