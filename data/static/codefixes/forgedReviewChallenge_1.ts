const { ObjectId } = require('mongodb')
module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const id = req.body.id;
    if (typeof id !== 'string' || !ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid review id' });
    }
    const message = req.body.message;
    if (typeof message !== 'string') {
      return res.status(400).json({ error: 'Invalid message' });
    }
    const user = security.authenticatedUsers.from(req)
    db.reviewsCollection.update(
      { _id: new ObjectId(id) },
      { $set: { message: message, author: user.data.email } },
      { multi: true }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
