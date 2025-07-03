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
          // generate salt and derive key using scrypt
          const salt = randomBytes(16).toString('hex')
          const derivedKey = scryptSync(clearTextPassword, salt, 64).toString('hex')
          this.setDataValue('password', `${salt}:${derivedKey}`)
        }
      },
