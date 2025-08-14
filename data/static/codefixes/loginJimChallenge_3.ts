import {BasketModel} from "../../../models/basket";
const loginAttempts: Record<string, { count: number, timer: NodeJS.Timeout | null }> = {};
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
    models.sequelize.query(`SELECT * FROM Users WHERE email = ? AND password = ? AND deletedAt IS NULL`,
      { replacements: [ req.body.email, req.body.password ], model: models.User, plain: true })
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
          const email = req.body.email;
          const attempt = loginAttempts[email] || { count: 0, timer: null };
          attempt.count++;
          if (attempt.count === 1) {
            attempt.timer = setTimeout(() => { delete loginAttempts[email]; }, LOCK_TIME);
          }
          loginAttempts[email] = attempt;
          if (attempt.count > MAX_ATTEMPTS) {
            return res.status(429).send(res.__('Too many login attempts. Please try again later.'));
          }
          return res.status(401).send(res.__('Invalid email or password.'));
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
