/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketModel } from '../models/basket'

const security = require('../lib/insecurity')

module.exports = function applyCoupon () {
  return (req: Request & { user?: { id: number } }, res: Response, next: NextFunction) => {
    const userId = req.user?.id
    if (!userId) {
      return res.status(403).send('Forbidden.')
    }
    const id = req.params.id
    let coupon: string | undefined | null = req.params.coupon ? decodeURIComponent(req.params.coupon) : undefined
    const discount = security.discountFromCoupon(coupon)
    coupon = discount ? coupon : null
    BasketModel.findOne({ where: { id: id, UserId: userId } }).then((basket: BasketModel | null) => {
      if (basket != null) {
        basket.update({ coupon: coupon?.toString() }).then(() => {
          if (discount) {
            res.json({ discount })
          } else {
            res.status(404).send('Invalid coupon.')
          }
        }).catch((error: Error) => {
          next(error)
        })
      } else {
        res.status(403).send('Forbidden.')
      }
    }).catch((error: Error) => {
      next(error)
    })
  }
}
