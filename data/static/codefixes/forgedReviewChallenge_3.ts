module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    db.reviewsCollection.update(
      { _id: req.body.id, author: user.id },
      { $set: { message: req.body.message } }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        if (result.modified === 0) {
          return res.status(403).json({ error: 'Forbidden' })
        }
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
