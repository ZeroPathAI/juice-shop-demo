/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'

import jwt from 'jsonwebtoken'
import challengeUtils = require('../lib/challengeUtils')

const privacyProofRateLimits: Map<string, { count: number; timestamp: number }> = new Map()

module.exports = function servePrivacyPolicyProof () {
  return (req: Request, res: Response) => {
    const ip = req.ip
    let entry = privacyProofRateLimits.get(ip)
    if (!entry || Date.now() - entry.timestamp > 60000) {
      entry = { count: 1, timestamp: Date.now() }
    } else if (entry.count < 5) {
      entry.count++
    } else {
      return res.status(429).send('Too many requests')
    }
    privacyProofRateLimits.set(ip, entry)

    const authHeader = req.headers.authorization
    if (!authHeader) {
      return res.status(401).send('Authentication required')
    }
    const [scheme, token] = authHeader.split(' ')
    if (scheme !== 'Bearer' || !token) {
      return res.status(401).send('Invalid authorization header')
    }
    let payload: any
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET!)
    } catch {
      return res.status(401).send('Invalid or expired token')
    }
    if (!payload.privacyPolicyAccepted) {
      return res.status(403).send('Privacy policy not accepted')
    }
    challengeUtils.solveIf(challenges.privacyPolicyProofChallenge, () => payload.privacyPolicyAccepted)
    res.sendFile(path.resolve('frontend/dist/frontend/assets/private/thank-you.jpg'))
  }
}
