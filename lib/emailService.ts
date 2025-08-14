import nodemailer from 'nodemailer'
import config from 'config'

const transporter = nodemailer.createTransport(config.get('smtp'))

export const sendPasswordChangeNotification = async (email: string): Promise<void> => {
  try {
    await transporter.sendMail({
      from: 'no-reply@juice-shop.com',
      to: email,
      subject: 'Password Change Notification',
      text: 'Your password was successfully changed. If you did not perform this action, please contact support immediately.'
    })
  } catch (error) {
    console.error(`Failed to send password change notification to ${email}`, error)
    throw error
  }
}
