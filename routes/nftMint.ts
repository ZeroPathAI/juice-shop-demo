import { type Request, type Response } from 'express'
import challengeUtils = require('../lib/challengeUtils')
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
const nftABI = require('../data/static/contractABIs').nftABI
const ethers = require('ethers')
const nftAddress = '0x41427790c94E7a592B17ad694eD9c06A02bb9C39'
const addressesMinted = new Set()
let isEventListenerCreated = false

module.exports.nftMintListener = function nftMintListener () {
  return (req: Request, res: Response) => {
    try {
      const provider = new ethers.WebSocketProvider('wss://eth-sepolia.g.alchemy.com/v2/FZDapFZSs1l6yhHW4VnQqsi18qSd-3GJ')
      const contract = new ethers.Contract(nftAddress, nftABI, provider)
      if (!isEventListenerCreated) {
        contract.on('NFTMinted', (minter: string) => {
          if (!addressesMinted.has(minter)) {
            addressesMinted.add(minter)
          }
        })
        isEventListenerCreated = true
      }
      res.status(200).json({ success: true, message: 'Event Listener Created' })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}

module.exports.walletNFTVerify = function walletNFTVerify () {
  return (req: Request, res: Response) => {
    try {
      const { walletAddress: metamaskAddress, signedMessage, signature } = req.body
      // verify address ownership
      try {
        const recoveredAddress = ethers.utils.verifyMessage(signedMessage, signature)
        if (recoveredAddress.toLowerCase() !== metamaskAddress.toLowerCase()) {
          return res.status(403).json({ success: false, message: 'Unauthorized address', status: challenges.nftMintChallenge })
        }
      } catch (sigError) {
        return res.status(400).json({ success: false, message: 'Invalid signature', status: challenges.nftMintChallenge })
      }
      if (addressesMinted.has(metamaskAddress)) {
        addressesMinted.delete(metamaskAddress)
        challengeUtils.solveIf(challenges.nftMintChallenge, () => true)
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftMintChallenge })
      } else {
        res.status(200).json({ success: false, message: 'Wallet did not mint the NFT', status: challenges.nftMintChallenge })
      }
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
