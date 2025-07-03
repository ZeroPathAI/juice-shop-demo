import { ObjectId } from 'mongodb'
import type { Request, Response, NextFunction } from 'express'

module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    let filter;
    try {
      filter = { _id: new ObjectId(req.body.id), author: user.data.email }
    } catch (err) {
      return res.status(400).json({ error: 'Invalid id' })
    }
    db.reviewsCollection.update(
      filter,
      { $set: { message: req.body.message } }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
