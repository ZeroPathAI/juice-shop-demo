import { ObjectId } from 'mongodb';

module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    // sanitize and validate id to prevent NoSQL injection and strip HTML tags
    let reviewId;
    try {
      reviewId = new ObjectId(String(req.body.id));
    } catch (e) {
      return res.status(400).json({ error: 'Invalid review id' });
    }
    const safeMessage = String(req.body.message).replace(/[<>]/g, '');
    db.reviewsCollection.update(
      { _id: reviewId },
      { $set: { message: safeMessage } }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
