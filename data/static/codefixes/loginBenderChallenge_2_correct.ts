import {BasketModel} from "../../../models/basket";
const MAX_FAILED_ATTEMPTS = 5;
const failedLoginAttempts: Record<string, number> = {};

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
          failedLoginAttempts[user.data.email] = 0;
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
          failedLoginAttempts[user.data.email] = 0;
          afterLogin(user, res, next)
        } else {
          const email = req.body.email;
          failedLoginAttempts[email] = (failedLoginAttempts[email] || 0) + 1;
          if (failedLoginAttempts[email] >= MAX_FAILED_ATTEMPTS) {
            return res.status(429).send(res.__('Too many failed login attempts. Please try again later.'));
          }
          res.status(401).send(res.__('Invalid email or password.'));
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
