/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'
import jwt from 'jsonwebtoken'
import rateLimit from 'express-rate-limit'

const logFileRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many requests, please try again later.'
})

module.exports = function serveLogFiles () {
  return [
    logFileRateLimiter,
    (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization as string | undefined
    if (!authHeader) {
      console.warn(`[LOGFILE_ACCESS] Unauthorized access attempt from ${req.ip}`)
      res.sendStatus(401)
      return
    }
    const token = authHeader.split(' ')[1]
    let payload: any
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET as string)
    } catch (err) {
      console.warn(`[LOGFILE_ACCESS] Invalid token from ${req.ip}`)
      res.sendStatus(401)
      return
    }
    if (!payload.roles || !payload.roles.includes('admin')) {
      console.warn(`[LOGFILE_ACCESS] Forbidden access by user ${payload.id} from ${req.ip}`)
      res.sendStatus(403)
      return
    }
    const file = req.params.file
    console.info(`[LOGFILE_ACCESS] User ${payload.id} accessing file ${file} from ${req.ip}`)

    if (!file.includes('/')) {
      res.sendFile(path.resolve('logs/', file))
    } else {
      console.warn(`[LOGFILE_ACCESS] Forbidden filename attempt: ${file} by user ${payload.id}`)
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
