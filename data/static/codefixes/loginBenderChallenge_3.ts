import {BasketModel} from "../../../models/basket";

const loginAttempts: Map<string, number> = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME_MS = 15 * 60 * 1000; // 15 minutes lockout
const lockedEmails: Map<string, number> = new Map();

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
    models.sequelize.query(`SELECT * FROM Users WHERE email = :mail AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
      { replacements: { mail: req.body.email }, model: models.User, plain: true })
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
          const now = Date.now();
          const lockExpires = lockedEmails.get(email) || 0;
          if (now < lockExpires) {
            return res.status(429).send(res.__('Too many login attempts. Please try again later.'));
          }
          const attempts = loginAttempts.get(email) || 0;
          const newAttempts = attempts + 1;
          loginAttempts.set(email, newAttempts);
          if (newAttempts >= MAX_LOGIN_ATTEMPTS) {
            lockedEmails.set(email, now + LOCK_TIME_MS);
            loginAttempts.delete(email);
            return res.status(429).send(res.__('Too many login attempts. Please try again later.'));
          }
          res.status(401).send(res.__('Invalid email or password.'));
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
