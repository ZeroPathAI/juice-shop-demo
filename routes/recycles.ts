/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'

import * as utils from '../lib/utils'

exports.getRecycleItem = () => (req: Request, res: Response) => {
  const idParam = parseInt(req.params.id, 10);
  if (isNaN(idParam)) {
    return res.status(400).send(utils.queryResultToJson({ err: 'Invalid id parameter' }));
  }
  RecycleModel.findAll({
    where: {
      id: idParam
    }
  }).then((Recycle) => {
    return res.send(utils.queryResultToJson(Recycle))
  }).catch((_: unknown) => {
    return res.send('Error fetching recycled items. Please try again')
  })
}

exports.blockRecycleItems = () => (req: Request, res: Response) => {
  const errMsg = { err: 'Sorry, this endpoint is not supported.' }
  return res.send(utils.queryResultToJson(errMsg))
}
