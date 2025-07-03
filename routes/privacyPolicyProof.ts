/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'

import challengeUtils = require('../lib/challengeUtils')
import jwt from 'jsonwebtoken'

const rateLimits = new Map<string, { count: number, timestamp: number }>()
const MAX_REQUESTS = 10
const WINDOW_SIZE = 60 * 1000

module.exports = function servePrivacyPolicyProof () {
  return (req: Request, res: Response) => {
    const authHeader = req.headers.authorization!
    const tokenMatch = authHeader.match(/^Bearer (.+)$/)
    if (!tokenMatch) {
      res.status(400).send('Malformed Authorization header')
      return
    }
    const token = tokenMatch[1]
    let payload: any
    try {
      payload = jwt.verify(token, process.env.AUTH_SECRET as string)
    } catch (err) {
      res.status(401).send('Invalid token')
      return
    }
    // Rate limiting
    const ip = req.ip
    const now = Date.now()
    let rate = rateLimits.get(ip)
    if (!rate || now - rate.timestamp > WINDOW_SIZE) {
      rate = { count: 1, timestamp: now }
    } else {
      rate.count += 1
    }
    rateLimits.set(ip, rate)
    if (rate.count > MAX_REQUESTS) {
      res.status(429).send('Too Many Requests')
      return
    }
    // Permission check
    if (!payload.permissions || !payload.permissions.includes('privacyPolicyProof')) {
      res.status(403).send('Forbidden')
      return
    }
    challengeUtils.solveIf(challenges.privacyPolicyProofChallenge, () => true)
    res.sendFile(path.resolve('frontend/dist/frontend/assets/private/thank-you.jpg'))
  }
}
