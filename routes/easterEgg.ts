/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'

import challengeUtils = require('../lib/challengeUtils')

module.exports = function serveEasterEgg () {
  return (req: Request, res: Response) => {
    // Session validation
    if (!req.session || !req.session.userId) {
      return res.status(401).send('Unauthorized')
    }

    // Verify previous challenge completion
    if (!challengeUtils.isSolved(challenges.easterEggLevelOneChallenge)) {
      return res.status(403).send('Forbidden')
    }
    // Solve level two challenge after passing validation
    challengeUtils.solveIf(challenges.easterEggLevelTwoChallenge, () => true)
    res.sendFile(path.resolve('frontend/dist/frontend/assets/private/threejs-demo.html'))
  }
}
