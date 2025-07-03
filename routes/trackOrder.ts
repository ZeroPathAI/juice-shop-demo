/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import utils = require('../lib/utils')
import challengeUtils = require('../lib/challengeUtils')
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'

module.exports = function trackOrder () {
  return async (req: Request, res: Response) => {
    // Verify user is authenticated
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' })
    }

    const id = String(req.params.id).replace(/[^\w-]+/g, '')

    try {
      // Use secure query and include user check
      const order = await db.ordersCollection.findOne({
        orderId: id,
        userId: req.user.id
      })

      if (!order) {
        return res.status(404).json({ error: 'Order not found' })
      }

      res.json({ data: [order] })
    } catch (error) {
      res.status(500).json({ error: 'Internal server error' })
    }
  }
}
