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
  return (req: Request, res: Response) => {
    const id = !utils.isChallengeEnabled(challenges.reflectedXssChallenge) ? String(req.params.id).replace(/[^\w-]+/g, '') : req.params.id

    challengeUtils.solveIf(challenges.reflectedXssChallenge, () => { return utils.contains(id, '<iframe src="javascript:alert(`xss`)">') })
    db.ordersCollection.find({ $where: `this.orderId === '${id}'` }).then((order: any) => {
      const result = utils.queryResultToJson(order)
      // Ensure the authenticated user owns the order
      const userId = (req as any).auth?.data?.id
      result.data = result.data.filter((o: any) => o.userId === userId)
      if (result.data.length === 0) {
        return res.status(403).json({ error: 'Forbidden' })
      }
      challengeUtils.solveIf(challenges.noSqlOrdersChallenge, () => { return result.data.length > 1 })
      if (result.data[0] === undefined) {
        result.data[0] = { orderId: id }
      }
      res.json(result)
    }, () => {
      res.status(400).json({ error: 'Wrong Param' })
    })
  }
}
