import {BasketModel} from "../../../models/basket";

module.exports = function login () {
  const failedLoginAttempts: { [email: string]: { count: number, lockUntil?: number } } = {};
  const MAX_FAILED_ATTEMPTS = 5;
  const LOCK_DURATION_MS = 15 * 60 * 1000;
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
    const email = req.body.email;
    const attemptInfo = failedLoginAttempts[email] || { count: 0 };
    if (attemptInfo.lockUntil && attemptInfo.lockUntil > Date.now()) {
      return res.status(429).send(res.__('Too many login attempts. Please try again later.'));
    }
    models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL`,
      { bind: [ req.body.email, security.hash(req.body.password) ], model: models.User, plain: true })
      .then((authenticatedUser) => {
        const user = utils.queryResultToJson(authenticatedUser)
        if (user.data?.id && user.data.totpSecret !== '') {
          failedLoginAttempts[email] = { count: 0 };
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
          failedLoginAttempts[email] = { count: 0 };
          afterLogin(user, res, next)
        } else {
          const newCount = (attemptInfo.count || 0) + 1;
          if (newCount >= MAX_FAILED_ATTEMPTS) {
            attemptInfo.lockUntil = Date.now() + LOCK_DURATION_MS;
          }
          failedLoginAttempts[email] = { count: newCount, lockUntil: attemptInfo.lockUntil };
          res.status(401).send(res.__('Invalid email or password.'))
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
