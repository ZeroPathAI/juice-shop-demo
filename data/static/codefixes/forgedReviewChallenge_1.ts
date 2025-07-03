module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    const reviewId = String(req.body.id)
    const newMessage = String(req.body.message)
    db.reviewsCollection.update(
      { _id: reviewId, author: user.data.email },
      { $set: { message: newMessage } }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
