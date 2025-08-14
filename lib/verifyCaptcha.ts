export async function verifyCaptcha(token: string): Promise<void> {
  const secret = process.env.CAPTCHA_SECRET
  if (!secret) {
    throw new Error('Missing CAPTCHA secret configuration')
  }
  const response = await fetch(
    'https://www.google.com/recaptcha/api/siteverify',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${secret}&response=${token}`
    }
  )
  const data: { success: boolean } = await response.json()
  if (!data.success) {
    throw new Error('Captcha verification failed')
  }
}
