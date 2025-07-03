import {BasketModel} from "../../../models/basket";
const loginRateLimits: Map<string, { count: number; last: number }> = new Map()

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
    // simple in-memory rate limiting per IP: max 5 attempts per minute
    const ip = req.ip
    const now = Date.now()
    const attempt = loginRateLimits.get(ip) || { count: 0, last: now }
    if (attempt.count >= 5 && now - attempt.last < 60000) {
      return res.status(429).send(res.__('Too many login attempts. Please try again later.'))
    }
    if (now - attempt.last >= 60000) {
      attempt.count = 0
    }
    attempt.count++
    attempt.last = now
    loginRateLimits.set(ip, attempt)
    models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL`,
      { bind: [ req.body.email, security.hash(req.body.password) ], model: models.User, plain: true })
      .then((authenticatedUser) => {
        const user = utils.queryResultToJson(authenticatedUser)
        // consistent response timing to prevent enumeration
        setTimeout(() => {
          if (user.data?.id && (!user.data.totpSecret || security.verifyTOTP(user.data.totpSecret, req.body.totpCode))) {
            afterLogin(user, res, next)
          } else {
            res.status(401).send(res.__('Invalid email or password.'))
          }
        }, 500)
      }).catch((error: Error) => {
        next(error)
      })
  }
