import {BasketModel} from "../../../models/basket";

const loginAttempts: Map<string, { count: number; lockedUntil?: number }> = new Map()
const MAX_ATTEMPTS = 5
const LOCK_TIME_MS = 15 * 60 * 1000 // 15 minutes

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
    const email = req.body.email || ''
    const now = Date.now()
    const attempt = loginAttempts.get(email) || { count: 0 }
    if (attempt.lockedUntil && attempt.lockedUntil > now) {
      return res.status(429).send(res.__('Too many login attempts. Please try again later.'))
    }
    models.sequelize.query(`SELECT * FROM Users WHERE email = '${email}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: false })
      .then((authenticatedUser) => {
        const user = utils.queryResultToJson(authenticatedUser)
        if (user.data?.id && user.data.totpSecret !== '') {
          res.status(401).json({
            status: 'totp_token_required',
            data: {
              tmpToken: security.authorize({
                userId: user.data.id,
                type: 'password_valid_needs_second_factor_token'
              })
            }
          })
        } else if (user.data?.id) {
          loginAttempts.delete(email)
          afterLogin(user, res, next)
        } else {
          const attempt = loginAttempts.get(email) || { count: 0 }
          attempt.count++
          if (attempt.count >= MAX_ATTEMPTS) {
            attempt.lockedUntil = Date.now() + LOCK_TIME_MS
          }
          loginAttempts.set(email, attempt)
          res.status(401).send(res.__('Invalid email or password.'))
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
