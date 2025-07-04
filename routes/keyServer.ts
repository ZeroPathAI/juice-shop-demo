/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'

module.exports = function serveKeyFiles () {
  return (req: Request, res: Response, next: NextFunction) => {
    // Session validation
    if (!req.session || !req.session.user) {
      res.status(401)
      return next(new Error('Authentication required to access key files'))
    }
    // Authorization: only admins can access
    const roles = Array.isArray(req.session.user.roles) ? req.session.user.roles : []
    if (!roles.includes('admin')) {
      res.status(403)
      return next(new Error('Unauthorized access to key files'))
    }
    const file = req.params.file

    if (!file.includes('/')) {
      res.sendFile(path.resolve(__dirname, '../encryptionkeys', file))
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
