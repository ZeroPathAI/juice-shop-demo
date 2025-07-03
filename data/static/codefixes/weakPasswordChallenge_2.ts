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
          const crypto = require('crypto')
          const salt = crypto.randomBytes(16).toString('hex')
          const derivedKey = crypto.scryptSync(clearTextPassword, salt, 64).toString('hex')
          this.setDataValue('password', `${salt}:${derivedKey}`)
        }
      },
