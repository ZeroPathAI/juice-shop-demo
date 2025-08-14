import crypto from 'crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import { PasswordResetTokenModel } from '../models/passwordResetToken'

const rateLimitMap: { [key: string]: { count: number; firstRequestAt: Date } } = {}

module.exports = function generatePasswordResetToken () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const email = req.body.email
      if (!email) {
        return res.status(400).send(res.__('Email is required.'))
      }
      const now = new Date()
      const rate = rateLimitMap[email] || { count: 0, firstRequestAt: now }
      if (rate.firstRequestAt.getTime() + 3600000 < now.getTime()) {
        rate.count = 0
        rate.firstRequestAt = now
      }
      rate.count++
      rateLimitMap[email] = rate
      if (rate.count > 5) {
        return res.status(429).send(res.__('Too many requests.'))
      }
      const user = await UserModel.findOne({ where: { email } })
      if (!user) {
        return res.status(404).send(res.__('User not found.'))
      }
      const token = crypto.randomBytes(32).toString('hex')
      const expiresAt = new Date(Date.now() + 3600000)
      await PasswordResetTokenModel.create({ token, userId: user.id, expiresAt })
      // TODO: send email with reset link containing token
      res.json({ token })
    } catch (error) {
      next(error)
    }
  }
}
