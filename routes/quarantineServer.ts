/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'

module.exports = function serveQuarantineFiles () {
  return (req: Request, res: Response, next: NextFunction) => {
    const { params, query } = req
    const file = params.file

    // Ensure the user is authenticated and authorized
    if (!req.user || !req.user.isAdmin) {
      res.status(403)
      next(new Error('Not authorized to access quarantine files!'))
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
