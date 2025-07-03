import {BasketModel} from "../../../models/basket";
import * as crypto from "crypto";

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
    models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND deletedAt IS NULL`,
      { bind: [ req.body.email ], model: models.User, plain: true })
      .then((authenticatedUser) => {
        const user = utils.queryResultToJson(authenticatedUser)
        // Constant-time password verification
        const submittedHash = Buffer.from(security.hash(req.body.password), 'utf8')
        const storedHash = Buffer.from(user.data.password, 'utf8')
        if (submittedHash.length !== storedHash.length || !crypto.timingSafeEqual(submittedHash, storedHash)) {
          return res.status(401).send(res.__('Invalid email or password.'))
        }
        // TOTP verification if enabled
        if (user.data.totpSecret) {
          const totpValid = security.verifyTOTP(user.data.totpSecret, req.body.totpCode)
          if (!totpValid) {
            return res.status(401).send(res.__('Invalid email or password.'))
          }
        }
        return afterLogin(user, res, next)
      }).catch((error: Error) => {
        next(error)
      })
  }
