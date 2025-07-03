/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'

import challengeUtils = require('../lib/challengeUtils')
import security = require('../lib/security')

module.exports = function servePrivacyPolicyProof () {
  return (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      res.status(401).send('Authentication required')
      return
    }
    challengeUtils.solveIf(challenges.privacyPolicyProofChallenge, () => { return true })
    res.sendFile(path.resolve('frontend/dist/frontend/assets/private/thank-you.jpg'))
  }
}
