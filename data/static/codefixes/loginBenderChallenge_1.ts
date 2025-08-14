import {BasketModel} from "../../../models/basket";

module.exports = function login () {
  const MAX_FAILED_LOGIN = 5
  const LOCK_TIME_MS = 15 * 60 * 1000 // 15 minutes
  const failedLoginAttempts: Map<string, number> = new Map()
  const lockoutExpiry: Map<string, number> = new Map()

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
    const lockUntil = lockoutExpiry.get(email) || 0
    if (now < lockUntil) {
      return res.status(423).send(res.__('Account locked due to multiple failed login attempts.'))
    }
    if (req.body.email.match(/.*['-;].*/) || req.body.password.match(/.*['-;].*/)) {
      res.status(451).send(res.__('SQL Injection detected.'))
    }
    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: true })
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
          const attempts = (failedLoginAttempts.get(req.body.email) || 0) + 1
          failedLoginAttempts.set(req.body.email, attempts)
          if (attempts >= MAX_FAILED_LOGIN) {
            lockoutExpiry.set(req.body.email, Date.now() + LOCK_TIME_MS)
            failedLoginAttempts.delete(req.body.email)
            return res.status(423).send(res.__('Account locked due to multiple failed login attempts.'))
          }
          return res.status(401).send(res.__('Invalid email or password.'))
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
