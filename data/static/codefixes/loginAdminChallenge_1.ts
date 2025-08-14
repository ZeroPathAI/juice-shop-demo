import {BasketModel} from "../../../models/basket";

module.exports = function login () {
  // Track failed login attempts per email
  const loginFailures: Record<string, number> = {}
  function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {
    // reset failures on successful login
    delete loginFailures[user.data.email]
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
          // reset failures on valid password
          delete loginFailures[email]
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
          loginFailures[email] = (loginFailures[email] || 0) + 1
          res.status(401).send(res.__('Invalid email or password.'))
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
