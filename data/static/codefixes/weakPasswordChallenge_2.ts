import bcrypt from 'bcrypt'

// TODO: Plan migration for existing MD5 password hashes.
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
          const salt = bcrypt.genSaltSync(12)
          // use bcrypt with key stretching
          const hash = bcrypt.hashSync(clearTextPassword, salt)
          this.setDataValue('password', hash)
        }
      },
