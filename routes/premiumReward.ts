/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'

import challengeUtils = require('../lib/challengeUtils')
import security = require('../lib/insecurity')

module.exports = function servePremiumContent () {
  return (req: Request, res: Response) => {
    const authenticatedUser = security.authenticatedUsers.from(req)
    if (!authenticatedUser) {
      res.status(401).send('Authentication required')
      return
    }
    challengeUtils.solveIf(challenges.premiumPaywallChallenge, () => { return true })
    res.sendFile(path.resolve('frontend/dist/frontend/assets/private/JuiceShop_Wallpaper_1920x1080_VR.jpg'))
  }
}
