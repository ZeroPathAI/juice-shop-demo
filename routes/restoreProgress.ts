/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import Hashids = require('hashids/cjs')
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'

const challengeUtils = require('../lib/challengeUtils')

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
  const restoreFindItRateLimitStore: Record<number, { count: number; firstTs: number }> = {}
  return async (req: Request & { user?: { id: number } }, res: Response) => {
    // Authentication
    if (!req.user) {
      return res.status(401).send('Authentication required.')
    }
    const { params } = req
    const hashids = new Hashids('this is the salt for findIt challenges', 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
    const continueCodeFindIt = params.continueCode
    const decoded = hashids.decode(continueCodeFindIt)
    // Validation
    if (decoded.length < 2) {
      return res.status(400).send('Invalid continue code.')
    }
    const [codeUserId, ...idsFindIt] = decoded
    // Authorization
    if (codeUserId !== req.user.id) {
      return res.status(403).send('Forbidden.')
    }
    // Rate Limiting
    const now = Date.now()
    const record = restoreFindItRateLimitStore[req.user.id] || { count: 0, firstTs: now }
    if (now - record.firstTs < 5 * 60 * 1000) {
      record.count += 1
      if (record.count > 10) {
        return res.status(429).send('Too many requests.')
      }
    } else {
      record.count = 1
      record.firstTs = now
    }
    restoreFindItRateLimitStore[req.user.id] = record
    // Logging
    console.log(`[RestoreProgressFindIt] user ${req.user.id} restoring ${idsFindIt.length} challenges at ${new Date().toISOString()}`)
    // Restore
    for (const key in challenges) {
      if (Object.prototype.hasOwnProperty.call(challenges, key) && idsFindIt.includes(challenges[key].id)) {
        await challengeUtils.solveFindIt(key, true)
      }
    }
    res.json({ data: idsFindIt.length + ' solved challenges have been restored.' })
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
