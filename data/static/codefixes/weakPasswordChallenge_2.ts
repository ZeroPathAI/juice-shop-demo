import crypto from 'crypto'
User.init(
      password: {
        type: DataTypes.STRING,
        set (clearTextPassword: string) {
          validatePasswordHasAtLeastOneNumber(clearTextPassword)
          validatePasswordHasAtLeastOneSpecialChar(clearTextPassword)
          validatePasswordHasAtLeastOneUpperCaseChar(clearTextPassword)
          validatePasswordHasAtLeastOneLowerCaseChar(clearTextPassword)
          validatePasswordHasAtLeastTenChar(clearTextPassword)
          validatePasswordIsNotInTopOneMillionCommonPasswordsList(clearTextPassword)
          const salt = crypto.randomBytes(16).toString('hex')
          const hash = crypto.pbkdf2Sync(clearTextPassword, salt, 100000, 64, 'sha512').toString('hex')
          this.setDataValue('password', `${salt}:${hash}`)
        }
      },
