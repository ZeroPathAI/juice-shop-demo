/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import Hashids = require('hashids/cjs')
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'

const challengeUtils = require('../lib/challengeUtils')

// Authentication, authorization, rate limiting and logging for restoreProgressFindIt
interface RateLimitEntry { count: number; firstRequest: number }
const findItRateLimitMap = new Map<number, RateLimitEntry>()
const FINDIT_WINDOW_MS = 60 * 1000
const FINDIT_MAX_REQUESTS = 5

module.exports.restoreProgress = function restoreProgress () {
  return ({ params }: Request, res: Response) => {
    const hashids = new Hashids('this is my salt', 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
    const continueCode = params.continueCode
    const ids = hashids.decode(continueCode)
    if (challengeUtils.notSolved(challenges.continueCodeChallenge) && ids.includes(999)) {
      challengeUtils.solve(challenges.continueCodeChallenge)
      res.end()
    } else if (ids.length > 0) {
      for (const name in challenges) {
        if (Object.prototype.hasOwnProperty.call(challenges, name)) {
          if (ids.includes(challenges[name].id)) {
            challengeUtils.solve(challenges[name], true)
          }
        }
      }
      res.json({ data: ids.length + ' solved challenges have been restored.' })
    } else {
      res.status(404).send('Invalid continue code.')
    }
  }
}

module.exports.restoreProgressFindIt = function restoreProgressFindIt () {
  return async (req: Request & { user?: { id: number } }, res: Response) => {
    // Authentication
    if (!req.user) {
      console.warn(`[restoreProgressFindIt] Unauthenticated access attempt`)
      return res.status(401).json({ message: 'Authentication required.' })
    }
    // Rate limiting
    const userId = req.user.id
    const now = Date.now()
    const entry = findItRateLimitMap.get(userId)
    if (entry) {
      if (now - entry.firstRequest < FINDIT_WINDOW_MS) {
        if (entry.count >= FINDIT_MAX_REQUESTS) {
          console.warn(`[restoreProgressFindIt] Rate limit exceeded for user ${userId}`)
          return res.status(429).json({ message: 'Too many requests. Please try again later.' })
        }
        entry.count++
      } else {
        entry.count = 1
        entry.firstRequest = now
      }
    } else {
      findItRateLimitMap.set(userId, { count: 1, firstRequest: now })
    }
    const hashids = new Hashids('this is the salt for findIt challenges', 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
    const continueCodeFindIt = req.params.continueCode
    console.info(`[restoreProgressFindIt] User ${userId} attempts restore with code ${continueCodeFindIt}`)
    const idsFindIt = hashids.decode(continueCodeFindIt)
    // Verify code belongs to user: first element must be user ID
    if (idsFindIt[0] !== userId) {
      console.warn(`[restoreProgressFindIt] User ${userId} provided invalid code ${continueCodeFindIt}`)
      return res.status(403).json({ message: 'Forbidden. Code does not belong to user.' })
    }
    const challengeIds = idsFindIt.slice(1)
    if (challengeIds.length > 0) {
      for (const key in challenges) {
        if (Object.prototype.hasOwnProperty.call(challenges, key)) {
          if (idsFindIt.includes(challenges[key].id)) {
            await challengeUtils.solveFindIt(key, true)
          }
        }
      }
      console.info(`[restoreProgressFindIt] User ${userId} restored ${challengeIds.length} challenges`)
      res.json({ data: challengeIds.length + ' solved challenges have been restored.' })
    } else {
      res.status(404).send('Invalid continue code.')
    }
  }
}

module.exports.restoreProgressFixIt = function restoreProgressFixIt () {
  const hashids = new Hashids('yet another salt for the fixIt challenges', 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
  return async ({ params }: Request, res: Response) => {
    const continueCodeFixIt = params.continueCode
    const idsFixIt = hashids.decode(continueCodeFixIt)
    if (idsFixIt.length > 0) {
      for (const key in challenges) {
        if (Object.prototype.hasOwnProperty.call(challenges, key)) {
          if (idsFixIt.includes(challenges[key].id)) {
            await challengeUtils.solveFixIt(key, true)
          }
        }
      }
      res.json({ data: idsFixIt.length + ' solved challenges have been restored.' })
    } else {
      res.status(404).send('Invalid continue code.')
    }
  }
}
