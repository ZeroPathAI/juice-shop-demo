/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'

module.exports = function serveLogFiles () {
  return (req: Request, res: Response, next: NextFunction) => {
    const { params } = req
    if (!req.user || !req.user.isAdmin) {
      res.status(403)
      return next(new Error('Unauthorized'))
    }
    const file = params.file

    if (!file.includes('/')) {
      res.sendFile(path.resolve('logs/', file))
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
