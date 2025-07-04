/* Generated API endpoints */
  finale.initialize({ app, sequelize })

  const autoModels = [
    { name: 'User', exclude: ['password', 'totpSecret'], model: UserModel },
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

    // enforce authentication on all CRUD operations for this resource
    resource.list.fetch.before((req, res, context) => {
      if (!req.user) { res.status(401).json({ error: 'Unauthorized' }); return; }
      return context.continue;
    });
    resource.read.fetch.before((req, res, context) => {
      if (!req.user) { res.status(401).json({ error: 'Unauthorized' }); return; }
      return context.continue;
    });
    resource.update.send.before((req, res, context) => {
      if (!req.user) { res.status(401).json({ error: 'Unauthorized' }); return; }
      delete req.body.isAdmin;
      return context.continue;
    });
    resource.delete.fetch.before((req, res, context) => {
      if (!req.user) { res.status(401).json({ error: 'Unauthorized' }); return; }
      return context.continue;
    });

    // create a wallet when a new user is registered using API
    if (name === 'User') {
      resource.create.send.before((req: Request, res: Response, context: { instance: { id: any }, continue: any }) => {
        // remove isAdmin from request
        delete req.body.isAdmin;
        // enforce admin-only access
        if (!req.user || req.user.role !== 'admin') {
          res.status(403).json({ error: 'Forbidden' })
          return
        }
        // create a wallet when a new user is registered using API
        WalletModel.create({ UserId: context.instance.id }).catch((err: unknown) => {
          console.log(err)
        })
        context.instance.role = context.instance.role ? context.instance.role : 'customer'
        return context.continue
      })
    }
