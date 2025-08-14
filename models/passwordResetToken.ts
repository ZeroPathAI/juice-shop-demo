import { DataTypes, Model } from 'sequelize'
import { sequelize } from '../models/index'

export class PasswordResetTokenModel extends Model {
  public token!: string
  public userId!: number
  public expiresAt!: Date
  public used!: boolean
}

PasswordResetTokenModel.init({
  token: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  userId: {
    type: DataTypes.INTEGER,
    allowNull: false
  },
  expiresAt: {
    type: DataTypes.DATE,
    allowNull: false
  },
  used: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  }
}, {
  sequelize,
  modelName: 'PasswordResetToken',
  timestamps: false
})
