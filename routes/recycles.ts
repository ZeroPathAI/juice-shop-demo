/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'
import { isAuthorized, authenticatedUsers } from '../lib/insecurity'

import * as utils from '../lib/utils'

exports.getRecycleItem = () => [
  isAuthorized(),
  (req: Request, res: Response) => {
    const authUser = authenticatedUsers.from(req)
    if (!authUser) {
      return res.status(401).json({ status: 'error', error: 'Unauthorized' })
    }
    RecycleModel.findAll({
      where: {
        id: JSON.parse(req.params.id),
        UserId: authUser.data.id
      }
    }).then((Recycle) => {
      return res.send(utils.queryResultToJson(Recycle))
    }).catch((_: unknown) => {
      return res.send('Error fetching recycled items. Please try again')
    })
  }
]

exports.blockRecycleItems = () => (req: Request, res: Response) => {
  const errMsg = { err: 'Sorry, this endpoint is not supported.' }
  return res.send(utils.queryResultToJson(errMsg))
}
