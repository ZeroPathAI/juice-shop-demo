import {BasketModel} from "../../../models/basket";
const failedAttempts: { [key: string]: { count: number; firstAttempt: number } } = {};
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_WINDOW_MS = 15 * 60 * 1000;

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
    if (req.body.email.match(/.*['-;].*/) || req.body.password.match(/.*['-;].*/)) {
      res.status(451).send(res.__('SQL Injection detected.'))
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
          const emailKey = req.body.email || '';
          const now = Date.now();
          let record = failedAttempts[emailKey] || { count: 0, firstAttempt: now };
          if (now - record.firstAttempt > LOCKOUT_WINDOW_MS) {
            record = { count: 1, firstAttempt: now };
          } else {
            record.count += 1;
          }
          failedAttempts[emailKey] = record;
          if (record.count >= MAX_FAILED_ATTEMPTS) {
            return res.status(429).send(res.__('Too many failed attempts. Please try again later.'));
          }
          res.status(401).send(res.__('Invalid email or password.'));
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
