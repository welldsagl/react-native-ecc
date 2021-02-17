'use strict'

import { NativeModules } from 'react-native'
import { Buffer } from 'buffer'
import hasher from 'hash.js'

const { RNECC } = NativeModules

const preHash = RNECC.preHash !== false
const algorithm = 'sha256'
const encoding = 'base64'
const curve = 'secp256r1'
const bits = 256

let serviceID
let accessGroup

module.exports = {
  setServiceID,
  getServiceID,
  setAccessGroup,
  getAccessGroup,
  generateKeys,
  sign,
  verify,
  hasKeys,
}

function setServiceID (id) {
  if (serviceID) throw new Error('serviceID can only be set once')

  serviceID = id
}

function getServiceID () {
  return serviceID
}

function setAccessGroup (val) {
  if (accessGroup) throw new Error('accessGroup can only be set once')

  accessGroup = val
}

function getAccessGroup () {
  return accessGroup
}

/**
 * Generates public and private keys.
 *
 * The public key is returned with the given callback.
 * The private key is saved in the Keychain/Keystore.
 *
 * @param {function} callback Callback invoked when the generation finishes. It
 * will be called with an error if the generation fails or with the public key
 * if it succeeds.
 */
function generateKeys(callback) {
  checkServiceID()
  assert(typeof callback === 'function')

  RNECC.generateECPair({
    service: serviceID,
    accessGroup: accessGroup,
    curve,
    bits,
  }, callback)
}

/**
 * Sign some data with a given public key.
 *
 * The user will be prompted with biometric authentication to sign data.
 *
 * @param {string} publicKey Public key to use to sign given data. The key must
 * have been generated with the `generateKeys` method.
 * @param {string} data Data to sign.
 * @param {string} promptTitle Title of the biometric prompt.
 * @param {string} promptMessage Message of the biometric prompt.
 * @param {string} promptCancel Label of cancel button of the biometric prompt.
 * @param {function} callback Callback invoked when the sign finishes. Will be
 * called with an error if the signing fails or with signed data if it succeeds.
 */
function sign({ publicKey, data, promptTitle, promptMessage, promptCancel }, callback) {
  checkServiceID()
  assert(typeof publicKey === 'string')
  assert(typeof data === 'string')
  assert(typeof callback === 'function')

  const opts = {
    service: serviceID,
    accessGroup: accessGroup,
    pub: publicKey,
    promptTitle,
    promptMessage,
    promptCancel,
  }

  if (preHash) {
    opts.hash = getHash(data)
  } else {
    opts.data = data
    opts.algorithm = algorithm
  }

  console.log('opts', opts);

  RNECC.sign(opts, callback)
}

/**
 * Verify that some data has been signed correctly.
 *
 * @param {string} publicKey Public key needed to verify given data. The key
 * must have been generated with the `generateKeys` method.
 * @param {string} data Data pre-signing.
 * @param {string} signedData Signed data.
 * @param {function} callback Callback invoked when the verification finishes.
 * It will be called with an error if the verification fails or with true/false
 * if it succeeds.
 */
function verify({ publicKey, data, signedData }, callback) {
  assert(typeof data === 'string')
  assert(typeof publicKey === 'string')
  assert(typeof callback === 'function')

  const opts = {
    pub: publicKey,
    sig: signedData,
  }

  if (preHash) {
    opts.hash = getHash(data)
  } else {
    opts.data = data
    opts.algorithm = algorithm
  }

  RNECC.verify(opts, callback);
}

/**
 * Check whether private and public keys have been generated.
 *
 * @param {string} publicKey The public key we need to check the existence of.
 * @param {function} callback Callback invoked when the check finishes. Will be
 * called with an error if the check fails or with true/false if it succeeds.
 */
function hasKeys({ publicKey }, callback) {
  checkServiceID()
  assert(typeof publicKey === 'string')

  RNECC.hasKey({
    service: serviceID,
    accessGroup: accessGroup,
    pub: publicKey,
  }, callback);
}

function assert (statement, errMsg) {
  if (!statement) throw new Error(errMsg || 'assertion failed')
}

function checkServiceID () {
  if (!serviceID) {
    throw new Error('call setServiceID() first')
  }
}

function getHash (data) {
  const arr = hasher[algorithm]().update(data).digest()
  return new Buffer(arr).toString(encoding)
}
