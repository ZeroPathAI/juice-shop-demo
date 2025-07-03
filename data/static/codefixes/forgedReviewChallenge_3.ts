module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    const id = req.body.id
    if (typeof id !== 'string' || !/^[a-fA-F0-9]{24}$/.test(id)) {
      return res.status(400).json({ error: 'Invalid review id' })
    }
    const sanitizedMessage = String(req.body.message).replace(/</g, '&lt;').replace(/>/g, '&gt;')
    db.reviewsCollection.update(
      { _id: req.body.id },
      { $set: { message: sanitizedMessage } }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
