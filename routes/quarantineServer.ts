/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'

module.exports = function serveQuarantineFiles () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      res.status(401)
      return next(new Error('Authentication required to download quarantine files'))
    }
    const { params, query } = req
    const file = params.file

    if (!file.includes('/')) {
      res.sendFile(path.resolve('ftp/quarantine/', file))
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
