/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'

import * as utils from '../lib/utils'
import jwt from 'jsonwebtoken'
import security from '../lib/security'
import { UserModel } from '../models/user'

exports.getRecycleItem = () => async (req: Request, res: Response) => {
  const authHeader = req.headers.authorization
  if (!authHeader) {
    return res.status(401).send(utils.queryResultToJson({ err: 'Authentication required' }))
  }
  const token = authHeader.split(' ')[1]
  let payload: any
  try {
    payload = jwt.verify(token, security.publicKey)
  } catch (err) {
    return res.status(401).send(utils.queryResultToJson({ err: 'Invalid token' }))
  }
  const user = await UserModel.findByPk(payload.data?.id)
  if (!user) {
    return res.status(401).send(utils.queryResultToJson({ err: 'Invalid user' }))
  }
  try {
    const items = await RecycleModel.findAll({
      where: {
        id: JSON.parse(req.params.id),
        userId: user.id
      }
    })
    return res.send(utils.queryResultToJson(items))
  } catch (err) {
    return res.status(500).send(utils.queryResultToJson({ err: 'Error fetching recycled items. Please try again' }))
  }
}

exports.blockRecycleItems = () => (req: Request, res: Response) => {
  const errMsg = { err: 'Sorry, this endpoint is not supported.' }
  return res.send(utils.queryResultToJson(errMsg))
}
