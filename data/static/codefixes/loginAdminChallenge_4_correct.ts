import {BasketModel} from "../../../models/basket";

module.exports = function login () {
  function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {
    BasketModel.findOrCreate({ where: { UserId: user.data.id } })
      .then(([basket]: [BasketModel, boolean]) => {
        const token = security.authorize(user)
        user.bid = basket.id // keep track of original basket
        security.authenticatedUsers.put(token, user)
        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })
      }).catch((error: Error) => {
        next(error)
      })
  }

  return (req: Request, res: Response, next: NextFunction) => {
    models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL`,
      { bind: [ req.body.email, security.hash(req.body.password) ], model: models.User, plain: true })
      .then((authenticatedUser) => {
        const user = utils.queryResultToJson(authenticatedUser)
        // Always return generic 401 for missing/invalid credentials or 2FA failures
        if (!user.data?.id) {
          return res.status(401).send(res.__('Invalid email or password.'))
        }
        // Handle 2FA if enabled
        if (user.data.totpSecret) {
          const totp = req.body.totp
          if (!totp || !security.verifyTotp(totp, user.data.totpSecret)) {
            return res.status(401).send(res.__('Invalid email or password.'))
          }
        }
        afterLogin(user, res, next)
      }).catch((error: Error) => {
        next(error)
      })
  }
