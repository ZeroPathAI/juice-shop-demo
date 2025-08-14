import {BasketModel} from "../../../models/basket";
const failedLoginAttempts = new Map<string, { count: number, lastAttempt: number }>();
const MAX_FAILED_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME_MS = 15 * 60 * 1000;

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
          afterLogin(user, res, next)
        } else {
          // Record failed login attempt
          const now = Date.now();
          const email = req.body.email;
          let attempt = failedLoginAttempts.get(email) || { count: 0, lastAttempt: now };
          if (now - attempt.lastAttempt > LOCKOUT_TIME_MS) {
            attempt = { count: 0, lastAttempt: now };
          }
          attempt.count++;
          attempt.lastAttempt = now;
          failedLoginAttempts.set(email, attempt);
          if (attempt.count > MAX_FAILED_LOGIN_ATTEMPTS) {
            return res.status(429).send(res.__('Too many failed login attempts. Please try again later.'));
          }
          res.status(401).send(res.__('Invalid email or password.'));
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
