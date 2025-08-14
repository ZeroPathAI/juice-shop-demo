/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { SecurityAnswerModel } from '../models/securityAnswer'
import { UserModel } from '../models/user'
import { SecurityQuestionModel } from '../models/securityQuestion'

const requestCounts: Record<string, { count: number, resetTime: number }> = {}

function verifyCaptcha(req: Request): boolean {
  const token = req.headers['x-captcha-token']
  return typeof token === 'string' && token.length > 0
}

function rateLimiter(req: Request, res: Response): boolean {
  const ip = req.ip
  let entry = requestCounts[ip]
  if (!entry) {
    entry = { count: 0, resetTime: Date.now() + 60 * 60 * 1000 }
  }
  if (Date.now() > entry.resetTime) {
    entry.count = 0
    entry.resetTime = Date.now() + 60 * 60 * 1000
  }
  entry.count++
  requestCounts[ip] = entry
  if (entry.count > 10) {
    res.status(429).json({ error: 'Too many requests' })
    return false
  }
  return true
}

module.exports = function securityQuestion () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!verifyCaptcha(req)) {
      res.status(400).json({ error: 'Invalid CAPTCHA' })
      return
    }
    if (!rateLimiter(req, res)) {
      return
    }
    const email = req.query.email
    SecurityAnswerModel.findOne({
      include: [{
        model: UserModel,
        where: { email: email?.toString() }
      }]
    }).then((answer: SecurityAnswerModel | null) => {
      if (answer != null) {
        SecurityQuestionModel.findByPk(answer.SecurityQuestionId).then((question: SecurityQuestionModel | null) => {
          // Return actual security question and set resetRequest cookie
          res.cookie('resetRequest', answer.SecurityQuestionId.toString(), { httpOnly: true })
          res.json({ question: question?.question || '' })
        }).catch((error: Error) => {
          next(error)
        })
      } else {
        // Dummy cookie to prevent enumeration and maintain consistent flow
        res.cookie('resetRequest', 'dummy', { httpOnly: true })
        res.json({})
      }
    }).catch((error: unknown) => {
      next(error)
    })
  }
}
