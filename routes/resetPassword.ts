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
import crypto from 'crypto'
const passwordResetTokens: Map<string, { userId: number; expires: Date }> = new Map()

module.exports = function resetPassword () {
  return ({ body, connection }: Request, res: Response, next: NextFunction) => {
    const email = body.email
    const answer = body.answer
    const newPassword = body.new
    const repeatPassword = body.repeat
    if (!email || !answer) {
      next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
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
          if (!body.token) {
            const token = crypto.randomBytes(32).toString('hex')
            const expires = new Date(Date.now() + 3600000) // 1 hour
            passwordResetTokens.set(token, { userId: data.UserId, expires })
            return res.json({ token, expires })
          }
          const tokenRecord = passwordResetTokens.get(body.token)
          if (!tokenRecord || tokenRecord.userId !== data.UserId || tokenRecord.expires < new Date()) {
            return res.status(401).send(res.__('Invalid or expired token.'))
          }
          passwordResetTokens.delete(body.token)
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
