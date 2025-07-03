/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'

import * as utils from '../lib/utils'
import { authMiddleware } from '../lib/auth'

exports.getRecycleItem = () => [
  authMiddleware,
  (req: Request, res: Response) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    RecycleModel.findAll({
      where: {
        id: JSON.parse(req.params.id),
        userId: req.user.id
      }
    }).then((Recycle) => {
      return res.send(utils.queryResultToJson(Recycle))
    }).catch((_: unknown) => {
      return res.status(500).json({ error: 'Error fetching recycled items. Please try again' })
    })
  }
];

exports.blockRecycleItems = () => (req: Request, res: Response) => {
  const errMsg = { err: 'Sorry, this endpoint is not supported.' }
  return res.send(utils.queryResultToJson(errMsg))
}
