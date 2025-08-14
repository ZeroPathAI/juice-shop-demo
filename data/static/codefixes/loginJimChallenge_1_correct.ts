import {BasketModel} from "../../../models/basket";

module.exports = function login () {
  const loginAttempts: Record<string, { count: number; lastAttempt: number }> = {};
  const MAX_LOGIN_ATTEMPTS = 5;
  const LOCK_TIME = 15 * 60 * 1000; // 15 minutes
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
    const key = req.ip;
    const now = Date.now();
    const record = loginAttempts[key] || { count: 0, lastAttempt: now };
    if (record.count >= MAX_LOGIN_ATTEMPTS && now - record.lastAttempt < LOCK_TIME) {
      return res.status(429).json({ status: 'too_many_requests' });
    }
    models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL`,
      { bind: [ req.body.email, security.hash(req.body.password) ], model: models.User, plain: true })
      .then((authenticatedUser) => {
        const user = utils.queryResultToJson(authenticatedUser)
        if (user.data?.id && user.data.totpSecret !== '') {
          delete loginAttempts[key];
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
          delete loginAttempts[key];
          afterLogin(user, res, next)
        } else {
          record.count++;
          record.lastAttempt = Date.now();
          loginAttempts[key] = record;
          res.status(401).send(res.__('Invalid email or password.'))
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
