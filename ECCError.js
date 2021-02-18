import { Platform } from 'react-native';

export const ErrorCode = {
  Canceled: 'canceled',
  BiometryNotAvailable: 'biometry-not-available',
  LockoutTemporarily: 'lockout-temporarily',
  LockoutPermanent: 'lockout-permanent',
  Generic: 'generic',
};

/**
 * Check: https://developer.android.com/reference/androidx/biometric/BiometricPrompt
 */
const AndroidErrorCode = {
  1: ErrorCode.BiometryNotAvailable,    // ERROR_HW_UNAVAILABLE
  2: ErrorCode.Generic,                 // ERROR_UNABLE_TO_PROCESS
  3: ErrorCode.Generic,                 // ERROR_TIMEOUT
  4: ErrorCode.Generic,                 // ERROR_NO_SPACE
  5: ErrorCode.Canceled,                // ERROR_CANCELED
  7: ErrorCode.LockoutTemporarily,      // ERROR_LOCKOUT
  8: ErrorCode.Generic,                 // ERROR_VENDOR
  9: ErrorCode.LockoutPermanent,        // ERROR_LOCKOUT_PERMANENT
  10: ErrorCode.Canceled,               // ERROR_USER_CANCELED
  11: ErrorCode.BiometryNotAvailable,   // ERROR_NO_BIOMETRICS
  12: ErrorCode.BiometryNotAvailable,   // ERROR_HW_NOT_PRESENT
  13: ErrorCode.Canceled,               // ERROR_NEGATIVE_BUTTON
  14: ErrorCode.BiometryNotAvailable,   // ERROR_NO_DEVICE_CREDENTIAL
  15: ErrorCode.Generic,                // ERROR_SECURITY_UPDATE_REQUIRED
  1000: ErrorCode.Generic,              // ERROR_INVALID_PROMPT_PARAMETERS (custom error)
  1001: ErrorCode.BiometryNotAvailable, // ERROR_INVALID_SIGNATURE (custom error)
};

/**
 * Check: TODO
 */
const IOSErrorCode = {
  // TODO.
};

export default class ECCError extends Error {
  constructor(nativeErrorCode) {
    super('ECC error');
    this.code = Platform.select({
      android: AndroidErrorCode[nativeErrorCode],
      ios: IOSErrorCode[nativeErrorCode],
    }) || ErrorCode.Generic;
    this.nativeCode = nativeErrorCode;
  }
}
