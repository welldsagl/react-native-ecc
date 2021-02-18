'use strict'

import { NativeModules } from 'react-native'
import bigInt from 'big-integer';
import { Buffer } from 'buffer'
import hasher from 'hash.js'
import ECCError, { ErrorCode } from './ECCError';

const { RNECC } = NativeModules

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
  computeCoordinates,
  ECCError,
  ErrorCode,
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

function promisify(fnWithCallback, params) {
  return new Promise((resolve, reject) => {
    fnWithCallback(params, (error, response) => {
      if (error) {
        reject(new ECCError(error))
      } else {
        resolve(response)
      }
    });
  });
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
function generateKeys() {
  checkServiceID()

  return promisify(RNECC.generateECPair, {
    service: serviceID,
    accessGroup: accessGroup,
    curve,
    bits,
  })
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
function sign({ publicKey, data, promptTitle, promptMessage, promptCancel }) {
  checkServiceID()
  assert(typeof publicKey === 'string')
  assert(typeof data === 'string')

  return promisify(RNECC.sign, {
    service: serviceID,
    accessGroup: accessGroup,
    pub: publicKey,
    hash: getHash(data),
    promptTitle,
    promptMessage,
    promptCancel,
  })
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
function verify({ publicKey, data, signedData }) {
  assert(typeof data === 'string')
  assert(typeof publicKey === 'string')

  return promisify(RNECC.verify, {
    pub: publicKey,
    sig: signedData,
    hash: getHash(data),
  })
}

/**
 * Check whether private and public keys have been generated.
 *
 * @param {string} publicKey The public key we need to check the existence of.
 * @param {function} callback Callback invoked when the check finishes. Will be
 * called with an error if the check fails or with true/false if it succeeds.
 */
function hasKeys({ publicKey }) {
  checkServiceID()
  assert(typeof publicKey === 'string')

  return promisify(RNECC.hasKey, {
    service: serviceID,
    accessGroup: accessGroup,
    pub: publicKey,
  })
}

/**
 * Compute x and y coordinates for a given base64 public key.
 *
 * @param {string} publicKeyBase64 Public key in base 64.
 * @return {{ x: string, y: string }} Coordinates of the given public key,
 * represented as strings because they are too long for numbers.
 */
function computeCoordinates(publicKeyBase64) {
  assert(typeof publicKeyBase64 === 'string')

  const publicKeyHex = Buffer.from(publicKeyBase64, 'base64').toString('hex');
  const publicKeyHexNo4 = publicKeyHex.slice(2);

  const xHex = publicKeyHexNo4.slice(0, 64);
  const yHex = publicKeyHexNo4.slice(64, 128);

  const x = bigInt(xHex, 16).toString();
  const y = bigInt(yHex, 16).toString();

  return { x, y };
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
