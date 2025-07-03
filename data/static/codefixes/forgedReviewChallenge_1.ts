const { ObjectId } = require('mongodb')

module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    // Validate id and message types
    if (typeof req.body.id !== 'string' || !ObjectId.isValid(req.body.id)) {
      return res.status(400).json({ error: 'Invalid review ID' })
    }
    if (typeof req.body.message !== 'string') {
      return res.status(400).json({ error: 'Invalid message content' })
    }
    db.reviewsCollection.update(
      { _id: new ObjectId(req.body.id), author: user.data.email },
      { $set: { message: req.body.message, author: user.data.email } },
      { multi: true }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
