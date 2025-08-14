import { type Request, type Response, type NextFunction } from 'express'
import { PasswordResetTokenModel } from '../models/passwordResetToken'
import { Op } from 'sequelize'

module.exports = function validateResetToken () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const token = req.body.token
      if (!token) {
        return res.status(400).send(res.__('Token is required.'))
      }
      const record = await PasswordResetTokenModel.findOne({
        where: { token, used: false, expiresAt: { [Op.gt]: new Date() } }
      })
      if (!record) {
        return res.status(400).send(res.__('Invalid or expired token.'))
      }
      res.json({ valid: true, userId: record.userId })
    } catch (error) {
      next(error)
    }
  }
}
