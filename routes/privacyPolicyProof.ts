/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'

import challengeUtils = require('../lib/challengeUtils')
const rateLimitMap = new Map<string, { count: number, lastReset: number }>();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 10;

module.exports = function servePrivacyPolicyProof () {
  return (req: Request, res: Response) => {
    // Authentication
    const user = (req as any).user;
    if (!user) {
      res.status(401).send('Unauthorized');
      return;
    }
    // Authorization: ensure user accepted privacy policy
    if (!user.acceptedPrivacyPolicy) {
      res.status(403).send('Privacy policy not accepted');
      return;
    }
    // Simple rate limiting per IP
    const ip = req.ip;
    const now = Date.now();
    const entry = rateLimitMap.get(ip) || { count: 0, lastReset: now };
    if (now - entry.lastReset > RATE_LIMIT_WINDOW) {
      entry.count = 0;
      entry.lastReset = now;
    }
    entry.count++;
    rateLimitMap.set(ip, entry);
    if (entry.count > MAX_REQUESTS_PER_WINDOW) {
      res.status(429).send('Too many requests');
      return;
    }
    // Referer header check as additional layer
    const referer = req.get('Referer') || '';
    if (!referer.includes('/privacy-policy')) {
      res.status(401).send('Unauthorized');
      return;
    }
    challengeUtils.solveIf(challenges.privacyPolicyProofChallenge, () => { return true })
    res.sendFile(path.resolve('frontend/dist/frontend/assets/private/thank-you.jpg'))
  }
}
