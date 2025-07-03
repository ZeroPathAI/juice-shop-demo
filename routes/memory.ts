/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { MemoryModel } from '../models/memory'
import { UserModel } from '../models/user'
import security from '../lib/security'

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
    const data = security.authenticatedUsers.from(req)
    if (!data || !data.data) {
      throw new Error('Need to login before getting memories')
    }
    const memories = await MemoryModel.findAll({ where: { UserId: data.data.id }, include: [UserModel] })
    res.status(200).json({ status: 'success', data: memories })
  }
}
