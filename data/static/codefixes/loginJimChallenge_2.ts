import {BasketModel} from "../../../models/basket";

module.exports = function login () {
  const loginAttempts: { [key: string]: { count: number; firstAttemptTime: number } } = {};
  const MAX_LOGIN_ATTEMPTS = 5;
  const LOCKOUT_DURATION_MS = 15 * 60 * 1000;
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
    const key = req.ip;
    const state = loginAttempts[key] || { count: 0, firstAttemptTime: Date.now() };
    if (state.count >= MAX_LOGIN_ATTEMPTS && (Date.now() - state.firstAttemptTime) < LOCKOUT_DURATION_MS) {
      return res.status(429).send(res.__('Too many login attempts. Please try again later.'));
    }
    if ((Date.now() - state.firstAttemptTime) >= LOCKOUT_DURATION_MS) {
      state.count = 0;
      state.firstAttemptTime = Date.now();
    }
    loginAttempts[key] = state;
    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: false })
      .then((authenticatedUser) => {
        const user = utils.queryResultToJson(authenticatedUser)
        if (user.data?.id && user.data.totpSecret !== '') {
          delete loginAttempts[key];
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
          delete loginAttempts[key];
          afterLogin(user, res, next)
        } else {
          const failState = loginAttempts[key] || { count: 0, firstAttemptTime: Date.now() };
          failState.count++;
          loginAttempts[key] = failState;
          res.status(401).send(res.__('Invalid email or password.'))
        }
      }).catch((error: Error) => {
        next(error)
      })
  }
