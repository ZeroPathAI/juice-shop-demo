import {BasketModel} from "../../../models/basket";
const failedLoginAttempts: Record<string, number> = {};
const MAX_LOGIN_ATTEMPTS = 5;

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
    const key = (req.body.email || '').toLowerCase();
    if ((failedLoginAttempts[key] || 0) >= MAX_LOGIN_ATTEMPTS) {
      res.status(429).send(res.__('Too many login attempts. Please try again later.'));
      return;
    }
    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: false })
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
          failedLoginAttempts[key] = 0;
          afterLogin(user, res, next)
        } else {
          failedLoginAttempts[key] = (failedLoginAttempts[key] || 0) + 1;
          res.status(401).send(res.__('Invalid email or password.'))
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
