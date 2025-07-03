const { ObjectId } = require('mongodb')

module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    let reviewId
    try {
      reviewId = new ObjectId(req.body.id)
    } catch (err) {
      return res.status(400).json({ error: 'Invalid review id' })
    }
    db.reviewsCollection.update(
      { _id: reviewId, author: user.id },
      { $set: { message: req.body.message } }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
