const { ObjectId } = require('mongodb')
module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    db.reviewsCollection.update(
      { _id: ObjectId(req.body.id), author: user._id },
      { $set: { message: String(req.body.message).replace(/</g, '&lt;').replace(/>/g, '&gt;') } }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
