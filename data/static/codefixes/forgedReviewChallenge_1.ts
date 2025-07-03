module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    const id = String(req.body.id)
    const message = String(req.body.message)
    db.reviewsCollection.update(
      { _id: id, author: user.data.email },
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
