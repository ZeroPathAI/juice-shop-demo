import {BasketModel} from "../../../models/basket";

const loginFailures: { [email: string]: { count: number; firstAttempt: number } } = {};
const MAX_FAILED_ATTEMPTS = 5;
const FAILED_WINDOW_MS = 60 * 60 * 1000; // 1 hour

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
    models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL`,
      { bind: [ req.body.email, security.hash(req.body.password) ], model: models.User, plain: true })
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
          // throttle failed login attempts
          const email = req.body.email;
          const now = Date.now();
          let record = loginFailures[email];
          if (!record || now - record.firstAttempt > FAILED_WINDOW_MS) {
            record = { count: 0, firstAttempt: now };
          }
          record.count++;
          loginFailures[email] = record;
          if (record.count > MAX_FAILED_ATTEMPTS) {
            res.status(429).send(res.__('Too many failed login attempts. Please try again later.'));
          } else {
            res.status(401).send(res.__('Invalid email or password.'));
          }
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
