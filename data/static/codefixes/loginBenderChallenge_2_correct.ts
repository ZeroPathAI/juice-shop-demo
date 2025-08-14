import {BasketModel} from "../../../models/basket";

module.exports = function login () {
  const MAX_FAILED_ATTEMPTS = 5
  const LOCKOUT_TIME_MS = 15 * 60 * 1000
  const failedLoginAttempts: Record<string, {count: number, lastAttempt: number}> = {}

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
    const attemptInfo = failedLoginAttempts[email];
    if (attemptInfo && attemptInfo.count >= MAX_FAILED_ATTEMPTS && (Date.now() - attemptInfo.lastAttempt) < LOCKOUT_TIME_MS) {
      return res.status(429).send(res.__('Too many login attempts. Please try again later.'));
    } else if (attemptInfo && (Date.now() - attemptInfo.lastAttempt) >= LOCKOUT_TIME_MS) {
      delete failedLoginAttempts[email];
    }
    models.sequelize.query(`SELECT * FROM Users WHERE email = $mail AND password = $pass AND deletedAt IS NULL`,
      { bind: { mail: req.body.email, pass: security.hash(req.body.password) }, model: models.User, plain: true })
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
          delete failedLoginAttempts[email];
          afterLogin(user, res, next)
        } else {
          const email = req.body.email;
          if (!failedLoginAttempts[email]) {
            failedLoginAttempts[email] = { count: 1, lastAttempt: Date.now() };
          } else {
            failedLoginAttempts[email].count++;
            failedLoginAttempts[email].lastAttempt = Date.now();
          }
          res.status(401).send(res.__('Invalid email or password.'));
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
