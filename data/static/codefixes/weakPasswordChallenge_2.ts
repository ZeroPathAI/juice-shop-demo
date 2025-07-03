import { randomBytes, scryptSync } from 'crypto'
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
          const salt = randomBytes(16).toString('hex')
          const hash = scryptSync(clearTextPassword, salt, 64).toString('hex')
          this.setDataValue('password', `${salt}:${hash}`)
        }
      },
