/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'

import challengeUtils = require('../lib/challengeUtils')

module.exports = function servePrivacyPolicyProof () {
  return (req: Request, res: Response) => {
    if ((req as any).isAuthenticated && (req as any).isAuthenticated()) {
      challengeUtils.solveIf(challenges.privacyPolicyProofChallenge, () => true)
      res.sendFile(path.resolve('frontend/dist/frontend/assets/private/thank-you.jpg'))
    } else {
      res.status(401).send('Authentication required')
    }
  }
}
