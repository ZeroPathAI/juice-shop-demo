/* Generated API endpoints */
  finale.initialize({ app, sequelize })

  const autoModels = [
    { name: 'User', exclude: ['password', 'totpSecret', 'isAdmin'], model: UserModel },
    { name: 'Product', exclude: [], model: ProductModel },
    { name: 'Feedback', exclude: [], model: FeedbackModel },
    { name: 'BasketItem', exclude: [], model: BasketItemModel },
    { name: 'Challenge', exclude: [], model: ChallengeModel },
    { name: 'Complaint', exclude: [], model: ComplaintModel },
    { name: 'Recycle', exclude: [], model: RecycleModel },
    { name: 'SecurityQuestion', exclude: [], model: SecurityQuestionModel },
    { name: 'SecurityAnswer', exclude: [], model: SecurityAnswerModel },
    { name: 'Address', exclude: [], model: AddressModel },
    { name: 'PrivacyRequest', exclude: [], model: PrivacyRequestModel },
    { name: 'Card', exclude: [], model: CardModel },
    { name: 'Quantity', exclude: [], model: QuantityModel }
  ]

  for (const { name, exclude, model } of autoModels) {
    const resource = finale.resource({
      model,
      endpoints: [`/api/${name}s`, `/api/${name}s/:id`],
      excludeAttributes: exclude,
      pagination: false
    })

    // enforce authentication and RBAC for User endpoints
    if (name === 'User') {
      // Middleware to ensure authentication
      const assertAuthenticated = (req: Request, res: Response, context: any) => {
        if (!req.user) {
          throw new Error('Authentication required')
        }
        return context.continue
      }
      // Middleware to ensure admin role
      const assertAdmin = (req: Request, res: Response, context: any) => {
        if (!req.user || req.user.role !== 'admin') {
          throw new Error('Admin privileges required')
        }
        return context.continue
      }
      // Protect list and read endpoints
      resource.list.fetch.before(assertAuthenticated)
      resource.read.fetch.before(assertAuthenticated)
      // Protect create endpoint with role validation and wallet creation
      resource.create.send.before((req: Request, res: Response, context: { instance: any, continue: any }) => {
        // override any client-supplied role/isAdmin for non-admin requests
        const isAdminRequest = req.user && req.user.role === 'admin'
        context.instance.role = isAdminRequest ? context.instance.role || 'customer' : 'customer'
        context.instance.isAdmin = isAdminRequest ? Boolean(context.instance.isAdmin) : false
        // create a wallet when a new user is registered
        WalletModel.create({ UserId: context.instance.id }).catch((err: unknown) => {
          console.log(err)
        })
        return context.continue
      })
      // Protect update and delete endpoints to admins only
      resource.update.send.before(assertAdmin)
      resource.delete.send.before(assertAdmin)
    }
