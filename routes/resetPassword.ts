/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response, type NextFunction } from 'express'
import type { Memory as MemoryConfig } from '../lib/config.types'
import { SecurityAnswerModel } from '../models/securityAnswer'
import { UserModel } from '../models/user'
import { challenges } from '../data/datacache'

import challengeUtils = require('../lib/challengeUtils')
const users = require('../data/datacache').users
const security = require('../lib/insecurity')
const RATE_LIMIT_WINDOW_MS = 60 * 1000
const MAX_RESET_PASSWORD_REQUESTS = 5
const resetPasswordAttempts: Record<string, { count: number, firstRequest: number }> = {}

module.exports = function resetPassword () {
  return async ({ body, connection }: Request, res: Response, next: NextFunction) => {
    const email = body.email
    const answer = body.answer
    const newPassword = body.new
    const repeatPassword = body.repeat
    if (!email || !answer) {
      next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
    } else {
      const ip = connection.remoteAddress
      const now = Date.now()
      let attempt = resetPasswordAttempts[ip]
      if (!attempt || now - attempt.firstRequest > RATE_LIMIT_WINDOW_MS) {
        resetPasswordAttempts[ip] = { count: 1, firstRequest: now }
      } else {
        attempt.count++
        if (attempt.count > MAX_RESET_PASSWORD_REQUESTS) {
          return res.status(429).send(res.__('Too many reset attempts, please try again later.'))
        }
      }
      const captchaValid = await security.verifyCaptcha(body.captcha)
      if (!captchaValid) {
        return res.status(401).send(res.__('Captcha verification failed.'))
      }
    } else if (!newPassword || newPassword === 'undefined') {
      res.status(401).send(res.__('Password cannot be empty.'))
    } else if (newPassword !== repeatPassword) {
      res.status(401).send(res.__('New and repeated password do not match.'))
    } else {
      SecurityAnswerModel.findOne({
        include: [{
          model: UserModel,
          where: { email }
        }]
      }).then((data: SecurityAnswerModel | null) => {
        if ((data != null) && security.hmac(answer) === data.answer) {
          UserModel.findByPk(data.UserId).then((user: UserModel | null) => {
            user?.update({ password: newPassword }).then((user: UserModel) => {
              verifySecurityAnswerChallenges(user, answer)
              res.json({ user })
            }).catch((error: unknown) => {
              next(error)
            })
          }).catch((error: unknown) => {
            next(error)
          })
        } else {
          res.status(401).send(res.__('Wrong answer to security question.'))
        }
      }).catch((error: unknown) => {
        next(error)
      })
    }
  }
}

function verifySecurityAnswerChallenges (user: UserModel, answer: string) {
  challengeUtils.solveIf(challenges.resetPasswordJimChallenge, () => { return user.id === users.jim.id && answer === 'Samuel' })
  challengeUtils.solveIf(challenges.resetPasswordBenderChallenge, () => { return user.id === users.bender.id && answer === 'Stop\'n\'Drop' })
  challengeUtils.solveIf(challenges.resetPasswordBjoernChallenge, () => { return user.id === users.bjoern.id && answer === 'West-2082' })
  challengeUtils.solveIf(challenges.resetPasswordMortyChallenge, () => { return user.id === users.morty.id && answer === '5N0wb41L' })
  challengeUtils.solveIf(challenges.resetPasswordBjoernOwaspChallenge, () => { return user.id === users.bjoernOwasp.id && answer === 'Zaya' })
  challengeUtils.solveIf(challenges.resetPasswordUvoginChallenge, () => { return user.id === users.uvogin.id && answer === 'Silence of the Lambs' })
  challengeUtils.solveIf(challenges.geoStalkingMetaChallenge, () => {
    const securityAnswer = ((() => {
      const memories = config.get<MemoryConfig[]>('memories')
      for (let i = 0; i < memories.length; i++) {
        if (memories[i].geoStalkingMetaSecurityAnswer) {
          return memories[i].geoStalkingMetaSecurityAnswer
        }
      }
    })())
    return user.id === users.john.id && answer === securityAnswer
  })
  challengeUtils.solveIf(challenges.geoStalkingVisualChallenge, () => {
    const securityAnswer = ((() => {
      const memories = config.get<MemoryConfig[]>('memories')
      for (let i = 0; i < memories.length; i++) {
        if (memories[i].geoStalkingVisualSecurityAnswer) {
          return memories[i].geoStalkingVisualSecurityAnswer
        }
      }
    })())
    return user.id === users.emma.id && answer === securityAnswer
  })
}
