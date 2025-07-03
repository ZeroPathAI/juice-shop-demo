/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import * as utils from '../utils'
import { Server } from 'socket.io'
import { notifications, challenges } from '../../data/datacache'
import * as challengeUtils from '../challengeUtils'
import * as security from '../insecurity'

let firstConnectedSocket: any = null

const globalWithSocketIO = global as typeof globalThis & {
  io: SocketIOClientStatic & Server
}

const registerWebsocketEvents = (server: any) => {
  const io = new Server(server, { cors: { origin: 'http://localhost:4200' } })
  // @ts-expect-error FIXME Type safety issue when setting global socket-io object
  globalWithSocketIO.io = io

  io.on('connection', (socket: any) => {
    // Authenticate user
    const token = socket.handshake.auth.token
    if (!security.verify(token)) {
      console.warn('Unauthorized websocket connection attempt')
      socket.emit('error', 'Unauthorized')
      socket.disconnect()
      return
    }
    const user = security.authenticatedUsers.get(token)
    if (!user) {
      socket.emit('error', 'Unauthorized')
      socket.disconnect()
      return
    }
    socket.data.user = user
    socket.data.rateLimit = {}

    if (firstConnectedSocket === null) {
      socket.emit('server started')
      firstConnectedSocket = socket.id
    }

    notifications.forEach((notification: any) => {
      socket.emit('challenge solved', notification)
    })

    socket.on('notification received', (data: any) => {
      const i = notifications.findIndex(({ flag }: any) => flag === data)
      if (i > -1) {
        notifications.splice(i, 1)
      }
    })

    socket.on('verifyLocalXssChallenge', (data: any) => {
      challengeUtils.solveIf(challenges.localXssChallenge, () => { return utils.contains(data, '<iframe src="javascript:alert(`xss`)">') })
      challengeUtils.solveIf(challenges.xssBonusChallenge, () => { return utils.contains(data, config.get('challenges.xssBonusPayload')) })
    })

    socket.on('verifySvgInjectionChallenge', (data: any) => {
      console.log(`User ${socket.data.user.data.id} verifySvgInjectionChallenge attempt with data: ${data}`)
      const key = 'verifySvgInjectionChallenge'
      const limit = { window: 60 * 1000, max: 10 }
      const now = Date.now()
      let rl = socket.data.rateLimit[key] || { count: 0, reset: now + limit.window }
      if (now > rl.reset) {
        rl = { count: 0, reset: now + limit.window }
      }
      rl.count++
      socket.data.rateLimit[key] = rl
      if (rl.count > limit.max) {
        socket.emit('error', 'Rate limit exceeded')
        return
      }
      const match = data?.match(/.*\.\.\/\.\.\/\.\.[\w/-]*?\/redirect\?to=https?:\/\/placekitten.com\/(g\/)?[\d]+\/[\d]+.*/)
      if (match && security.isRedirectAllowed(data)) {
        challengeUtils.solveIf(challenges.svgInjectionChallenge, () => true)
      }
    })

    socket.on('verifyCloseNotificationsChallenge', (data: any) => {
      console.log(`User ${socket.data.user.data.id} verifyCloseNotificationsChallenge attempt with data: ${JSON.stringify(data)}`)
      const key = 'verifyCloseNotificationsChallenge'
      const limit = { window: 60 * 1000, max: 10 }
      const now = Date.now()
      let rl = socket.data.rateLimit[key] || { count: 0, reset: now + limit.window }
      if (now > rl.reset) {
        rl = { count: 0, reset: now + limit.window }
      }
      rl.count++
      socket.data.rateLimit[key] = rl
      if (rl.count > limit.max) {
        socket.emit('error', 'Rate limit exceeded')
        return
      }
      if (Array.isArray(data) && data.length > 1) {
        challengeUtils.solveIf(challenges.closeNotificationsChallenge, () => true)
      }
    })
  })
}

export default registerWebsocketEvents
