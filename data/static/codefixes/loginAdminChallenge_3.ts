import {BasketModel}from "../../../models/basket";
const MAX_FAILED_ATTEMPTS = 5
const LOCK_TIME = 15 * 60 * 1000 // 15 minutes
const loginFailures: Record<string, { count: number, firstFailureTime: number }> = {}

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
    const email = req.body.email
    const failure = loginFailures[email]
    if (failure && failure.count >= MAX_FAILED_ATTEMPTS && Date.now() - failure.firstFailureTime < LOCK_TIME) {
      return res.status(429).send(res.__('Too many login attempts. Please try again later.'))
    }
    if (failure && Date.now() - failure.firstFailureTime >= LOCK_TIME) {
      delete loginFailures[email]
    }
    models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL`,
      { bind: [ req.body.email, req.body.password ], model: models.User, plain: true })
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
          afterLogin(user, res, next)
        } else {
          const now = Date.now()
          if (!loginFailures[email] || now - loginFailures[email].firstFailureTime >= LOCK_TIME) {
            loginFailures[email] = { count: 1, firstFailureTime: now }
          } else {
            loginFailures[email].count += 1
          }
          if (loginFailures[email].count >= MAX_FAILED_ATTEMPTS) {
            return res.status(429).send(res.__('Too many login attempts. Please try again later.'))
          }
          res.status(401).send(res.__('Invalid email or password.'))
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
