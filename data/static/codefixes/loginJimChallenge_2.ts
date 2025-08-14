import {BasketModel} from "../../../models/basket";
import LockoutService from "../../../services/lockoutService";

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
    const email = req.body.email || ''
    const passwordHash = security.hash(req.body.password || '')
    if (await LockoutService.isLocked(email)) {
      return res.status(423).json({ error: 'Account is locked due to too many failed login attempts' })
    }
    models.User.findOne({ where: { email, password: passwordHash, deletedAt: null } })
      .then(async (userModel) => {
        const user = userModel ? { data: userModel.get({ plain: true }) } : {}
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
          const attemptInfo = await LockoutService.recordFailedAttempt(email, new Date())
          if (attemptInfo.locked) {
            return res.status(423).json({ error: 'Account locked due to too many failed login attempts' })
          }
          const delay = LockoutService.getDelay(attemptInfo.attempts)
          setTimeout(() => {
            res.status(401).send(res.__('Invalid email or password.'))
          }, delay)
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
