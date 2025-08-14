/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { SecurityAnswerModel } from '../models/securityAnswer'
import { UserModel } from '../models/user'
import { SecurityQuestionModel } from '../models/securityQuestion'
import { verifyCaptcha } from '../lib/verifyCaptcha'

module.exports = function securityQuestion () {
  return (req: Request, res: Response, next: NextFunction) => {
    const email = req.query.email
    const responseToken = req.query.captchaToken?.toString()
    if (!responseToken) {
      return res.status(400).json({ error: 'Missing CAPTCHA token' })
    }
    verifyCaptcha(responseToken).then(() => {
      SecurityAnswerModel.findOne({
      include: [{
        model: UserModel,
        where: { email: email?.toString() }
      }]
    }).then((answer: SecurityAnswerModel | null) => {
      if (answer != null) {
        SecurityQuestionModel.findByPk(answer.SecurityQuestionId).then((question: SecurityQuestionModel | null) => {
          res.json({ question })
        }).catch((error: Error) => {
          next(error)
        })
      } else {
        res.json({})
      }
    }).catch((error: unknown) => {
      next(error)
    })
  }
}
