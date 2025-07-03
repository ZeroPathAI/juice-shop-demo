import {BasketModel} from "../../../models/basket";

module.exports = function login () {
  const loginAttempts = new Map<string, { count: number; firstAttempt: number }>()
  const MAX_ATTEMPTS = 5
  const WINDOW_MS = 60 * 1000

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
      const ip = req.ip
      let record = loginAttempts.get(ip)
      const now = Date.now()
      if (!record || now - record.firstAttempt > WINDOW_MS) {
        record = { count: 1, firstAttempt: now }
      } else {
        record.count++
      }
      loginAttempts.set(ip, record)
      if (record.count > MAX_ATTEMPTS) {
        res.status(429).send(res.__('Too many login attempts. Please try again later.'))
        return
      }
    models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL`,
      { bind: [ req.body.email, security.hash(req.body.password) ], model: models.User, plain: true })
      .then((authenticatedUser) => {
        const user = utils.queryResultToJson(authenticatedUser)
        if (user.data?.id) {
          afterLogin(user, res, next)
        } else {
          res.status(401).send(res.__('Invalid email or password.'))
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
