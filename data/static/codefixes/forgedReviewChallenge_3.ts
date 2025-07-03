module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    const safeId = String(req.body.id)
    const safeMessage = String(req.body.message)
    db.reviewsCollection.update(
      { _id: safeId },
      { $set: { message: safeMessage } }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
