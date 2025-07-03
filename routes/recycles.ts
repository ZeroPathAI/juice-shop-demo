/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'

import * as utils from '../lib/utils'
import jwt from 'jsonwebtoken'

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret'

function authenticate(req: Request) {
  const authHeader = req.headers.authorization
  if (!authHeader) throw { status: 401, message: 'No token provided' }
  const parts = authHeader.split(' ')
  if (parts.length !== 2 || parts[0] !== 'Bearer') throw { status: 400, message: 'Token malformatted' }
  try {
    return jwt.verify(parts[1], JWT_SECRET)
  } catch (err) {
    throw { status: 401, message: 'Invalid token' }
  }
}

exports.getRecycleItem = () => async (req: Request, res: Response) => {
  try {
    const decoded = authenticate(req) as { userId: number }
    const items = await RecycleModel.findAll({
      where: {
        id: JSON.parse(req.params.id),
        userId: decoded.userId
      }
    })
    return res.send(utils.queryResultToJson(items))
  } catch (err: any) {
    return res
      .status(err.status || 500)
      .send(utils.queryResultToJson({ err: err.message || 'Internal Server Error' }))
  }
}

exports.blockRecycleItems = () => (req: Request, res: Response) => {
  const errMsg = { err: 'Sorry, this endpoint is not supported.' }
  return res.send(utils.queryResultToJson(errMsg))
}
