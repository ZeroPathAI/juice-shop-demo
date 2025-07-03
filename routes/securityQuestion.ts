/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { SecurityAnswerModel } from '../models/securityAnswer'
import { UserModel } from '../models/user'
import { SecurityQuestionModel } from '../models/securityQuestion'

module.exports = function securityQuestion () {
  return (req: Request, res: Response, next: NextFunction) => {
    // Uniform response to prevent email enumeration
    // TODO: implement rate limiting to mitigate brute-force enumeration
    // Adding a fixed delay to reduce timing attack viability
    setTimeout(() => {
      res.json({
        question: null,
        message: 'If your email is registered, you will receive your security question shortly.'
      })
    }, 1000)
  }
}
