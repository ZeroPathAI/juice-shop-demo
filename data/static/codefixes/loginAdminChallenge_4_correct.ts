import {BasketModel} from "../../../models/basket";

const failedLoginAttempts: Record<string, { count: number; firstFailedAt: number; lockedUntil?: number }> = {};
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000;

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
    const attempt = failedLoginAttempts[email];
    if (attempt?.lockedUntil && Date.now() < attempt.lockedUntil) {
      const retryAfter = Math.ceil((attempt.lockedUntil - Date.now()) / 1000);
      return res.status(429).json({
        status: 'account_locked',
        retryAfter
      });
    }
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
          // track failed login attempts
          const now = Date.now();
          if (!failedLoginAttempts[email]) {
            failedLoginAttempts[email] = { count: 1, firstFailedAt: now };
          } else {
            failedLoginAttempts[email].count++;
          }
          if (failedLoginAttempts[email].count >= MAX_FAILED_ATTEMPTS) {
            failedLoginAttempts[email].lockedUntil = now + LOCKOUT_DURATION_MS;
          }
          res.status(401).send(res.__('Invalid email or password.'));
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
