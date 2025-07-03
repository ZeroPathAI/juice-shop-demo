/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'fs/promises'
import { type Request, type Response, type NextFunction } from 'express'
import { type User } from '../data/types'
import { UserModel } from '../models/user'
import jwt, { type JwtPayload, type VerifyErrors } from 'jsonwebtoken'
import challengeUtils = require('../lib/challengeUtils')
import logger from '../lib/logger'
import config from 'config'
import download from 'download'
import * as utils from '../lib/utils'
import { isString } from 'lodash'
import { Bot } from 'juicy-chat-bot'
import validateChatBot from '../lib/startup/validateChatBot'
import * as security from '../lib/insecurity'
import * as botUtils from '../lib/botUtils'
import { challenges } from '../data/datacache'

const ALLOWED_HANDLERS: Set<string> = new Set(Object.keys(botUtils))
const handlerInvocationLog: Array<{ userId: number, handler: string, timestamp: number }> = []
const handlerTimestamps: Map<string, number> = new Map()
const DEFAULT_HANDLER_INTERVAL_MS = 1000 // minimum interval between handler calls
const couponUseTimestamps: Map<number, number> = new Map()
const COUPON_INTERVAL_MS = 24 * 60 * 60 * 1000 // 1 day limit for coupon generation

let trainingFile = config.get<string>('application.chatBot.trainingData')
let testCommand: string
export let bot: Bot | null = null

export async function initialize () {
  if (utils.isUrl(trainingFile)) {
    const file = utils.extractFilename(trainingFile)
    const data = await download(trainingFile)
    await fs.writeFile('data/chatbot/' + file, data)
  }

  await fs.copyFile(
    'data/static/botDefaultTrainingData.json',
    'data/chatbot/botDefaultTrainingData.json'
  )

  trainingFile = utils.extractFilename(trainingFile)
  const trainingSet = await fs.readFile(`data/chatbot/${trainingFile}`, 'utf8')
  validateChatBot(JSON.parse(trainingSet))

  testCommand = JSON.parse(trainingSet).data[0].utterances[0]
  bot = new Bot(config.get('application.chatBot.name'), config.get('application.chatBot.greeting'), trainingSet, config.get('application.chatBot.defaultResponse'))
  return bot.train()
}

void initialize()

async function processQuery (user: User, req: Request, res: Response, next: NextFunction) {
  if (bot == null) {
    res.status(503).send()
    return
  }
  const username = user.username
  if (!username) {
    res.status(200).json({
      action: 'namequery',
      body: 'I\'m sorry I didn\'t get your name. What shall I call you?'
    })
    return
  }

  if (!bot.factory.run(`currentUser('${user.id}')`)) {
    try {
      bot.addUser(`${user.id}`, username)
      res.status(200).json({
        action: 'response',
        body: bot.greet(`${user.id}`)
      })
    } catch (err) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
    return
  }

  if (bot.factory.run(`currentUser('${user.id}')`) !== username) {
    bot.addUser(`${user.id}`, username)
    try {
      bot.addUser(`${user.id}`, username)
    } catch (err) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }
  }

  if (!req.body.query) {
    res.status(200).json({
      action: 'response',
      body: bot.greet(`${user.id}`)
    })
    return
  }

  try {
    const response = await bot.respond(req.body.query, `${user.id}`)
    if (response.action === 'function') {
      const handlerName = response.handler
      if (handlerName && ALLOWED_HANDLERS.has(handlerName)) {
        logger.info(`Handler invoked: ${handlerName} by user ${user.id}`)
        // rate limit all handlers per user
        const invocationKey = `${user.id}:${handlerName}`
        const lastInvocation = handlerTimestamps.get(invocationKey) ?? 0
        if (Date.now() - lastInvocation < DEFAULT_HANDLER_INTERVAL_MS) {
          res.status(429).json({ error: 'Handler invocation rate limit exceeded' })
          return
        }
        handlerTimestamps.set(invocationKey, Date.now())
        // special daily limit for couponCode
        if (handlerName === 'couponCode') {
          const now = Date.now()
          const lastTime = couponUseTimestamps.get(user.id) ?? 0
          if (now - lastTime < COUPON_INTERVAL_MS) {
            res.status(429).json({ error: 'Coupon code generation rate limit exceeded' })
            return
          }
          couponUseTimestamps.set(user.id, now)
        }
        try {
          // @ts-expect-error unclean usage of any type as index
          const result = await botUtils[handlerName](req.body.query, user)
          res.status(200).json(result)
          handlerInvocationLog.push({ userId: user.id, handler: handlerName, timestamp: Date.now() })
        } catch (err) {
          logger.error(`Error invoking handler ${handlerName}: ${utils.getErrorMessage(err)}`)
          res.status(500).json({ error: 'Error executing handler' })
        }
      } else {
        res.status(403).json({ error: 'Handler not allowed' })
      }
    } else {
      res.status(200).json(response)
    }
  } catch (err) {
    try {
      await bot.respond(testCommand, `${user.id}`)
      res.status(200).json({
        action: 'response',
        body: config.get('application.chatBot.defaultResponse')
      })
    } catch (err) {
      challengeUtils.solveIf(challenges.killChatbotChallenge, () => { return true })
      res.status(200).json({
        action: 'response',
        body: `Remember to stay hydrated while I try to recover from "${utils.getErrorMessage(err)}"...`
      })
    }
  }
}

async function setUserName (user: User, req: Request, res: Response) {
  if (bot == null) {
    return
  }
  try {
    const userModel = await UserModel.findByPk(user.id)
    if (userModel == null) {
      res.status(401).json({
        status: 'error',
        error: 'Unknown user'
      })
      return
    }
    const updatedUser = await userModel.update({ username: req.body.query })
    const updatedUserResponse = utils.queryResultToJson(updatedUser)
    const updatedToken = security.authorize(updatedUserResponse)
    // @ts-expect-error FIXME some properties missing in updatedUserResponse
    security.authenticatedUsers.put(updatedToken, updatedUserResponse)
    bot.addUser(`${updatedUser.id}`, req.body.query)
    res.status(200).json({
      action: 'response',
      body: bot.greet(`${updatedUser.id}`),
      token: updatedToken
    })
  } catch (err) {
    logger.error(`Could not set username: ${utils.getErrorMessage(err)}`)
    res.status(500).send()
  }
}

export const status = function status () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (bot == null) {
      res.status(200).json({
        status: false,
        body: `${config.get<string>('application.chatBot.name')} isn't ready at the moment, please wait while I set things up`
      })
      return
    }
    const token = req.cookies.token || utils.jwtFrom(req)
    if (!token) {
      res.status(200).json({
        status: bot.training.state,
        body: `Hi, I can't recognize you. Sign in to talk to ${config.get<string>('application.chatBot.name')}`
      })
      return
    }

    const user = await getUserFromJwt(token)
    if (user == null) {
      res.status(401).json({
        error: 'Unauthenticated user'
      })
      return
    }

    const username = user.username

    if (!username) {
      res.status(200).json({
        action: 'namequery',
        body: 'I\'m sorry I didn\'t get your name. What shall I call you?'
      })
      return
    }

    try {
      bot.addUser(`${user.id}`, username)
      res.status(200).json({
        status: bot.training.state,
        body: bot.training.state ? bot.greet(`${user.id}`) : `${config.get<string>('application.chatBot.name')} isn't ready at the moment, please wait while I set things up`
      })
    } catch (err) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}

module.exports.process = function respond () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (bot == null) {
      res.status(200).json({
        action: 'response',
        body: `${config.get<string>('application.chatBot.name')} isn't ready at the moment, please wait while I set things up`
      })
    }
    const token = req.cookies.token || utils.jwtFrom(req)
    if (!token) {
      res.status(400).json({
        error: 'Unauthenticated user'
      })
      return
    }

    const user = await getUserFromJwt(token)
    if (user == null) {
      res.status(401).json({
        error: 'Unauthenticated user'
      })
      return
    }

    if (req.body.action === 'query') {
      await processQuery(user, req, res, next)
    } else if (req.body.action === 'setname') {
      await setUserName(user, req, res)
    }
  }
}

async function getUserFromJwt (token: string): Promise<User | null> {
  return await new Promise((resolve) => {
    jwt.verify(token, security.publicKey, (err: VerifyErrors | null, decoded: JwtPayload | string | undefined) => {
      if (err !== null || !decoded || isString(decoded)) {
        resolve(null)
      } else {
        resolve(decoded.data)
      }
    })
  })
}
