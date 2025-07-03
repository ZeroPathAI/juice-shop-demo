/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { MemoryModel } from '../models/memory'
import { UserModel } from '../models/user'
import * as security from '../lib/security'

module.exports.addMemory = function addMemory () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const record = {
      caption: req.body.caption,
      imagePath: 'assets/public/images/uploads/' + req.file?.filename,
      UserId: req.body.UserId
    }
    const memory = await MemoryModel.create(record)
    res.status(200).json({ status: 'success', data: memory })
  }
}

module.exports.getMemories = function getMemories () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const auth = security.authenticatedUsers.from(req)
    if (!auth) {
      return res.status(401).json({ status: 'error', error: 'AuthenticationRequired' })
    }
    const memories = await MemoryModel.findAll({ where: { UserId: auth.data.id }, include: [UserModel] })
    res.status(200).json({ status: 'success', data: memories })
  }
}
