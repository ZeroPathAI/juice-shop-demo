/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'

module.exports = function serveLogFiles () {
  return (req: Request, res: Response, next: NextFunction) => {
    const file = req.params.file
    if (typeof (req as any).isAuthenticated !== 'function' || !(req as any).isAuthenticated()) {
      res.status(401)
      return next(new Error('Authentication required to access log files!'))
    }

    if (!file.includes('/')) {
      res.sendFile(path.resolve('logs/', file))
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
