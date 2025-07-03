import { randomBytes, pbkdf2Sync } from 'crypto';
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
          const salt = randomBytes(16).toString('hex');
          const key = pbkdf2Sync(clearTextPassword, salt, 100000, 64, 'sha512').toString('hex');
          this.setDataValue('password', `${salt}:${key}`);
        }
      },
