/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'
import jwt from 'jsonwebtoken'

// Simple in-memory rate limiter: max 20 requests per minute per user/IP
const rateLimitStore = new Map<string, number[]>()

module.exports = function serveQuarantineFiles () {
  return (req: Request, res: Response, next: NextFunction) => {
    const { params, query } = req
    const file = params.file

    // Logging access attempt
    console.info(`[${new Date().toISOString()}] Quarantine file access attempt: ${req.ip} -> ${file}`)

    const authHeader = req.headers.authorization
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      console.warn(`Unauthorized attempt without valid Bearer token from ${req.ip}`)
      res.status(401)
      next(new Error('Unauthorized access to quarantine files'))
      return
    }
    const token = authHeader.split(' ')[1]
    let user
    try {
      user = jwt.verify(token, process.env.JWT_SECRET as string)
    } catch (err) {
      console.warn(`Token verification failed for ${req.ip}: ${err}`)
      res.status(401)
      next(new Error('Invalid authentication token'))
      return
    }
    // Authorization check
    if (!user.permissions || !user.permissions.includes('quarantine:read')) {
      console.warn(`Forbidden: user ${(user as any).id} lacks permissions to access quarantine files`)
      res.status(403)
      next(new Error('Forbidden access to quarantine files'))
      return
    }
    // Rate limiting
    const key = (user as any).id || req.ip
    const now = Date.now()
    const windowMs = 60 * 1000
    const maxRequests = 20
    const timestamps = rateLimitStore.get(key) || []
    const recent = timestamps.filter(ts => now - ts < windowMs)
    recent.push(now)
    rateLimitStore.set(key, recent)
    if (recent.length > maxRequests) {
      console.warn(`Rate limit exceeded for ${key}`)
      res.status(429)
      next(new Error('Too many requests'))
      return
    }

    if (!file.includes('/')) {
      res.sendFile(path.resolve('ftp/quarantine/', file))
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
