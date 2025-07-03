/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'

import * as utils from '../lib/utils'

exports.getRecycleItem = () => (req: Request, res: Response) => {
  if (!req.user || !req.user.id) {
    return res.status(401).send(utils.queryResultToJson({ err: 'Unauthorized' }))
  }
  RecycleModel.findAll({
    where: {
      id: JSON.parse(req.params.id),
      userId: req.user.id
    }
  }).then((Recycle) => {
    if (Array.isArray(Recycle) && Recycle.length === 0) {
      return res.status(403).send(utils.queryResultToJson({ err: 'Forbidden' }))
    }
    return res.send(utils.queryResultToJson(Recycle))
  }).catch((_: unknown) => {
    return res.send('Error fetching recycled items. Please try again')
  })
}

exports.blockRecycleItems = () => (req: Request, res: Response) => {
  const errMsg = { err: 'Sorry, this endpoint is not supported.' }
  return res.send(utils.queryResultToJson(errMsg))
}
