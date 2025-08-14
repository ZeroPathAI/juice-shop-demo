import {BasketModel} from "../../../models/basket";
import { LockoutService } from "../../../services/lockoutService";
const failedLoginTracker: Map<string, { count: number; lastAttempt: number }> = new Map();
const MAX_FAILED_ATTEMPTS = 5;
const BASE_DELAY_MS = 1000; // 1 second

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
          const ip = req.ip || 'unknown';
          const now = Date.now();
          const record = failedLoginTracker.get(ip) || { count: 0, lastAttempt: 0 };
          if (record.lastAttempt > now) {
            const retryDelay = record.lastAttempt - now;
            console.error(`Throttling login attempts for IP ${ip}, retry after ${retryDelay}ms`);
            setTimeout(() => {
              res.status(429).send(res.__('Too many requests. Please try again later.'));
            }, retryDelay);
            return;
          }
          record.count++;
          if (record.count >= MAX_FAILED_ATTEMPTS) {
            LockoutService.lockAccount(req.body.email);
            console.error(`Locking account for IP ${ip}, email ${req.body.email}`);
            res.status(423).send(res.__('Account locked due to too many failed login attempts.'));
            return;
          }
          const delay = Math.pow(2, record.count - 1) * BASE_DELAY_MS;
          record.lastAttempt = now + delay;
          failedLoginTracker.set(ip, record);
          console.error(`Failed login attempt ${record.count} for IP ${ip}, delaying response by ${delay}ms`);
          setTimeout(() => {
            res.status(401).send(res.__('Invalid email or password.'));
          }, delay);
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
