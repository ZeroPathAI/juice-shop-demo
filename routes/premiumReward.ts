/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'

import security = require('../lib/insecurity')
import challengeUtils = require('../lib/challengeUtils')

module.exports = function servePremiumContent () {
  return (req: Request, res: Response) => {
    const userSession = security.authenticatedUsers.from(req)
    if (!userSession) {
      res.status(401).json({ error: 'Authentication required' })
      return
    }
    challengeUtils.solveIf(challenges.premiumPaywallChallenge, () => { return true })
    res.sendFile(path.resolve('frontend/dist/frontend/assets/private/JuiceShop_Wallpaper_1920x1080_VR.jpg'))
  }
}
