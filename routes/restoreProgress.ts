/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import Hashids = require('hashids/cjs')
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'
import crypto from 'crypto'
const SIGNING_SECRET = process.env.CONTINUE_CODE_SIGNING_SECRET
if (!SIGNING_SECRET) {
  throw new Error('Missing CONTINUE_CODE_SIGNING_SECRET environment variable')
}
const RATE_LIMIT_WINDOW_MS = 60 * 1000
const RATE_LIMIT_MAX_ATTEMPTS = 5
const rateLimitMap: Map<string, { count: number; timestamp: number }> = new Map()

const challengeUtils = require('../lib/challengeUtils')

module.exports.restoreProgress = function restoreProgress () {
  return ({ params, user, ip }: Request & { user?: any; ip: string }, res: Response) => {
    if (!user || !user.id) {
      return res.status(401).send('Authentication required')
    }
    const now = Date.now()
    const rl = rateLimitMap.get(ip) || { count: 0, timestamp: now }
    if (now - rl.timestamp < RATE_LIMIT_WINDOW_MS) {
      rl.count++
      if (rl.count > RATE_LIMIT_MAX_ATTEMPTS) {
        return res.status(429).send('Too many requests')
      }
    } else {
      rl.count = 1
      rl.timestamp = now
    }
    rateLimitMap.set(ip, rl)
    const [encodedCode, signature] = params.continueCode.split('.')
    const expectedSig = crypto.createHmac('sha256', SIGNING_SECRET).update(encodedCode).digest('hex')
    if (signature !== expectedSig) {
      return res.status(400).send('Invalid continue code.')
    }
    const hashids = new Hashids('this is my salt', 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
    const idsDecoded = hashids.decode(encodedCode)
    const userIdFromCode = idsDecoded.shift()
    if (user.id !== userIdFromCode) {
      return res.status(403).send('Forbidden')
    }
    const ids = idsDecoded
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
  return async ({ params, user, ip }: Request & { user?: any; ip: string }, res: Response) => {
    if (!user || !user.id) {
      return res.status(401).send('Authentication required')
    }
    const now = Date.now()
    const rl = rateLimitMap.get(ip) || { count: 0, timestamp: now }
    if (now - rl.timestamp < RATE_LIMIT_WINDOW_MS) {
      rl.count++
      if (rl.count > RATE_LIMIT_MAX_ATTEMPTS) {
        return res.status(429).send('Too many requests')
      }
    } else {
      rl.count = 1
      rl.timestamp = now
    }
    rateLimitMap.set(ip, rl)
    const [encodedCode, signature] = params.continueCode.split('.')
    const expectedSig = crypto.createHmac('sha256', SIGNING_SECRET).update(encodedCode).digest('hex')
    if (signature !== expectedSig) {
      return res.status(400).send('Invalid continue code.')
    }
    const hashids = new Hashids('this is the salt for findIt challenges', 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
    const idsDecoded = hashids.decode(encodedCode)
    const userIdFromCode = idsDecoded.shift()
    if (user.id !== userIdFromCode) {
      return res.status(403).send('Forbidden')
    }
    const idsFindIt = idsDecoded
    if (idsFindIt.length > 0) {
      for (const key in challenges) {
        if (Object.prototype.hasOwnProperty.call(challenges, key)) {
          if (idsFindIt.includes(challenges[key].id)) {
            await challengeUtils.solveFindIt(key, true)
          }
        }
      }
      res.json({ data: idsFindIt.length + ' solved challenges have been restored.' })
    } else {
      res.status(404).send('Invalid continue code.')
    }
  }
}

module.exports.restoreProgressFixIt = function restoreProgressFixIt () {
  const salt = process.env.FIXIT_CONTINUE_CODE_SALT
  if (!salt) {
    throw new Error('Missing FIXIT_CONTINUE_CODE_SALT environment variable')
  }
  const hashids = new Hashids(salt, 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
  return async ({ params, user, ip }: Request & { user?: any; ip: string }, res: Response) => {
    if (!user || !user.id) {
      return res.status(401).send('Authentication required')
    }
    const now = Date.now()
    const rl = rateLimitMap.get(ip) || { count: 0, timestamp: now }
    if (now - rl.timestamp < RATE_LIMIT_WINDOW_MS) {
      rl.count++
      if (rl.count > RATE_LIMIT_MAX_ATTEMPTS) {
        return res.status(429).send('Too many requests')
      }
    } else {
      rl.count = 1
      rl.timestamp = now
    }
    rateLimitMap.set(ip, rl)
    const [encodedCode, signature] = params.continueCode.split('.')
    const expectedSig = crypto.createHmac('sha256', SIGNING_SECRET).update(encodedCode).digest('hex')
    if (signature !== expectedSig) {
      return res.status(400).send('Invalid continue code.')
    }
    const idsDecoded = hashids.decode(encodedCode)
    const userIdFromCode = idsDecoded.shift()
    if (user.id !== userIdFromCode) {
      return res.status(403).send('Forbidden')
    }
    const idsFixIt = idsDecoded
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
