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
    if (!req.session?.authenticated) {
      res.status(401).json({ error: 'Authentication required' })
      return
    }
    challengeUtils.solveIf(challenges.easterEggLevelTwoChallenge, () => req.session?.authenticated === true)
    res.sendFile(path.resolve(path.normalize('frontend/dist/frontend/assets/private/threejs-demo.html')))
  }
}
