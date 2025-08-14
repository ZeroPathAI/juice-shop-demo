import {BasketModel} from "../../../models/basket";

const failedLoginAttempts: { [key: string]: { count: number, lastAttempt: number } } = {};
const MAX_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000;

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
    const email = req.body.email;
    const now = Date.now();
    const record = failedLoginAttempts[email] || { count: 0, lastAttempt: 0 };
    if (record.count >= MAX_ATTEMPTS && now - record.lastAttempt < LOCK_TIME) {
      return res.status(429).send(res.__('Too many login attempts. Please try again later.'));
    }
    models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL`,
      { bind: [ req.body.email, req.body.password ], model: models.User, plain: true })
      .then((authenticatedUser) => {
        const user = utils.queryResultToJson(authenticatedUser)
        if (user.data?.id && user.data.totpSecret !== '') {
          delete failedLoginAttempts[email];
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
          record.count += 1;
          record.lastAttempt = Date.now();
          failedLoginAttempts[email] = record;
          res.status(401).send(res.__('Invalid email or password.'))
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
