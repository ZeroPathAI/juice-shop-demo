import {BasketModel} from "../../../models/basket";
import LockoutService from "../../../services/LockoutService";
import RateLimiter from "../../../services/RateLimiter";

const MAX_FAILED_ATTEMPTS = 5;
const BASE_DELAY_MS = 1000;

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

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      await RateLimiter.consume(req.ip);
    } catch (err) {
      return res.status(429).send(res.__('Too many requests, please try again later.'));
    }
    models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
      { bind: [ req.body.email ], model: models.User, plain: true })
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
          const identifier = req.body.email || req.ip;
          // check account lockout status
          LockoutService.isLocked(identifier)
            .then((locked: boolean) => {
              if (locked) {
                return res.status(403).send(res.__('Account locked due to too many failed login attempts.'));
              }
              const attempts = LockoutService.incrementFailedAttempts(identifier);
              if (attempts >= MAX_FAILED_ATTEMPTS) {
                LockoutService.lockAccount(identifier);
                return res.status(403).send(res.__('Account locked due to too many failed login attempts.'));
              }
              const delay = BASE_DELAY_MS * Math.pow(2, attempts - 1);
              setTimeout(() => {
                res.status(401).send(res.__('Invalid email or password.'));
              }, delay);
            })
            .catch((error: Error) => {
              next(error);
            });
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
