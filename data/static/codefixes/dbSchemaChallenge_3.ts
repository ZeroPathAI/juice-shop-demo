const injectionChars = /"|'|;|and|or|;|#/i;

module.exports = function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
    if (criteria.match(injectionChars)) {
      res.status(400).send()
      return
    }
    const likeCriteria = `%${criteria}%`
    models.sequelize.query(
      `SELECT * FROM Products WHERE ((name LIKE :likeCriteria OR description LIKE :likeCriteria) AND deletedAt IS NULL) ORDER BY name`,
      { replacements: { likeCriteria }, type: models.sequelize.QueryTypes.SELECT }
    )
      .then((products: any[]) => {
        const dataString = JSON.stringify(products)
        for (let i = 0; i < products.length; i++) {
          products[i].name = req.__(products[i].name)
          products[i].description = req.__(products[i].description)
        }
        res.json(utils.queryResultToJson(products))
      }).catch((error: ErrorWithParent) => {
        next(error.parent)
      })
  }
}
