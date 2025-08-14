import {BasketModel} from "../../../models/basket";
const failedLoginAttempts: Map<string, { count: number, lockoutExpiry: number }> = new Map();
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_TIME_MS = 15 * 60 * 1000;

module.exports = function login () {
  function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {
    failedLoginAttempts.delete(user.data.email)
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
    if (req.body.email.match(/.*['-;].*/) || req.body.password.match(/.*['-;].*/)) {
      res.status(451).send(res.__('SQL Injection detected.'))
    }
    const email = req.body.email || '';
    const attempt = failedLoginAttempts.get(email);
    if (attempt && attempt.lockoutExpiry > Date.now()) {
      return res.status(429).send(res.__('Too many login attempts. Please try again later.'));
    } else if (attempt && attempt.lockoutExpiry <= Date.now()) {
      failedLoginAttempts.delete(email);
    }
    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: true })
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
          const record = failedLoginAttempts.get(email) || { count: 0, lockoutExpiry: 0 };
          record.count += 1;
          if (record.count >= MAX_FAILED_ATTEMPTS) {
            record.lockoutExpiry = Date.now() + LOCKOUT_TIME_MS;
            failedLoginAttempts.set(email, record);
            return res.status(429).send(res.__('Too many login attempts. Please try again later.'));
          }
          failedLoginAttempts.set(email, record);
          res.status(401).send(res.__('Invalid email or password.'));
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
