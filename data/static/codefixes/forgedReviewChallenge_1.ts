module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    const id = req.body.id
    if (typeof id !== 'string' || !/^[0-9a-fA-F]{24}$/.test(id)) {
      res.status(400).json({ error: 'Invalid id format' })
      return
    }
    db.reviewsCollection.update(
      { _id: id, author: user.data.email },
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
