module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    // prevent NoSQL injection by forcing primitives
    const id = String(req.body.id)
    const message = String(req.body.message)
    db.reviewsCollection.update(
      { _id: id },
      { $set: { message: message } }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
