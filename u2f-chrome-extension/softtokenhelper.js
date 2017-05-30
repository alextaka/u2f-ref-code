/**
 * @fileoverview A helper that generates signatures in-browser using E2E
 * crypto. FOR TESTING ONLY.
 * @author arnarb@google.com (Arnar Birgisson)
 */
'use strict';


function generateKey(opt_sk) {
  var key = e2e.ecc.Protocol.generateKeyPair(e2e.ecc.PrimeCurve.P_256, opt_sk);
  return new e2e.ecc.Ecdsa(e2e.ecc.PrimeCurve.P_256, key);
}

/**
 * @constructor
 * @param {!SoftTokenProfile} profile
 * @extends {GenericRequestHelper}
 */
function SoftTokenHelper(profile) {
  this.profile_ = profile;
  GenericRequestHelper.apply(this, []);

  this.registerHandlerFactory('enroll_helper_request', function(request) {
    return new SoftTokenEnrollHandler(profile, request);
  });
  this.registerHandlerFactory('sign_helper_request', function(request) {
    return new SoftTokenSignHandler(profile, request);
  });
}

inherits(SoftTokenHelper, GenericRequestHelper);


/** @typedef {{pub: ?string, sec: string}} */
var SoftTokenKeyPair;


/** @typedef {{
 *    appIdHash: string,
 *    keyHandle: string,
 *    keys: !SoftTokenKeyPair,
 *    counter: number,
 *    waitingOnTransferAccessMessageNumber: integer || undefined
 * }}
 */
var SoftTokenRegistration;

/** @typedef {{
 *     registration: !SoftTokenRegistration
 *     originalKeyHandle: string,
 *     transferAccessMessageChain: string
 * }}
 */
var SoftTokenTransferAccessChain;

/**
 * A key pair for testing. When non-null, will be used instead of generating
 * a random key pair on enroll.
 * @type {?SoftTokenKeyPair}
 */
SoftTokenHelper.keyPairForTesting = null;



/**
 * A soft token profile represents the state of a single token.
 * @constructor
 */
function SoftTokenProfile() {
  /**
   * The attestation private key as a hex string
   * @type {string}
   */
  this.attestationKey = SoftTokenProfile.DEFAULT_ATTESTATION_KEY;
  /**
   * The attestation certificate in X.509 as a hex string
   * @type {string}
   */
  this.attestationCert = SoftTokenProfile.DEFAULT_ATTESTATION_CERT;
  /**
   * Registrations (i.e. appId/keyHandle pairs) known to this key.
   * Keys are hex-encoded and appIdHash and keyHandle are base64-urlsafe.
   * @type {!Array<!SoftTokenRegistration>}
   */
  this.registrations = [];
  /**
   * TransferAccessChains (appId/keyHandle pairs) sent to this device.
   * Registration is as above.
   * originalKeyHandle is base64-urlsafe.
   * transferAccessMessageChain is hex encoded.
   * @type {!Array<!SoftTokenTransferAccessChain>}
   */
  this.transferAccessChains = [];
}


/**
 * A default attestation key, from U2F Raw Message Formats example section.
 * @const {string}
 */
SoftTokenProfile.DEFAULT_ATTESTATION_KEY =
    'f3fccc0d00d8031954f90864d43c247f4bf5f0665c6b50cc17749a27d1cf7664';


/**
 * A default attestation cert, from U2F Raw Message Formats example section.
 * @const {string}
 */
SoftTokenProfile.DEFAULT_ATTESTATION_CERT =
    '3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce' +
    '3d0403023017311530130603550403130c476e756262792050696c6f74301e17' +
    '0d3132303831343138323933325a170d3133303831343138323933325a303131' +
    '2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930' +
    '313238303030313135353935373335323059301306072a8648ce3d020106082a' +
    '8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668' +
    '2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02' +
    '03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd' +
    'b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220' +
    '631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df';


/**
 * Initializes a new registration record and stores in the profile.
 * @param {string} appIdHash in base64-urlsafe
 * @param {SoftTokenKeyPair} keypair
 * @return {!SoftTokenRegistration}
 */
SoftTokenProfile.prototype.createRegistration = function(appIdHash, keypair) {
  var registration = {
    appIdHash: appIdHash,
    keyHandle: B64_encode(new SHA256().digest(keypair.pub)),
    keys: {
      sec: keypair.sec,
      pub: keypair.pub
    },
    counter: 1
  };
  this.registrations.push(registration);
  return registration;
};

/**
 *                              //TODO: (what should we pass and return?
 * @return {boolean} Whether this could be run.
 **/
SoftTokenProfile.prototype.runTransferAccess = function() {
  // TODO: marks all keys to be transferred as waiting for message 2
  // TODO: creates a handler to listen for responses
  // 
};

/**
 * Initializes a new transferAccessChain and stores it in the profile.
 * @param {SoftTokenRegistration} registration
 * @param {string} originalKeyHandle
 * @param {string} transferAccessMessageChain
 * @return {!SoftTokenTransferAccessChain}
 */
SoftTokenProfile.prototype.createTransferAccessChain =
  function(registration, originalKeyHandle, transferAccessMessageChain) {
    let softTokenTransferAccessChain;
    softTokenTransferAccessChain = {
      registration: registration,
      originalKeyHandle: originalKeyHandle,
      transferAccessMessageChain: transferAccessMessageChain
    };

    this.transferAccessChains.push(softTokenTransferAccessChain);
    return softTokenTransferAccessChain;
};


/**
 * Builds a single transferAccessMessage
 * @param {integer} sequenceNumber
 * @param {string} newPublicKey in base64-urlsafe
 * @param {SoftTokenRegistration} registration
 * @param {string} newAttestationCert
 * @return {Uint8Array} 
 */
SoftTokenProfile.prototype.buildTransferAccessMessage =
  function(sequenceNumber, newPublicKey, registration, newAttestationCert) {
    const sequenceNumberLength = 1;
    const newPublicKeyBytes = UTIL_HexToBytes(newPublicKey);
    const appIdBytes = new Uint8Array(B64_decode(registration.appIdHash));
    const newAttestationCertBytes = UTIL_HexToBytes(newAttestationCert);

    const lengthOfSignBufferForSignatureUsingPrivateKey =
          sequenceNumberLength +
          newPublicKeyBytes.length +
          appIdBytes.length +
          newAttestationCertBytes.length;
    let signBufferForSignatureUsingPrivateKey =
        new Uint8Array(lengthOfSignBufferForSignatureUsingPrivateKey);

    const indexOfSequenceNumber = 0;
    signBufferForSignatureUsingPrivateKey[indexOfSequenceNumber] =
      0xFF & sequenceNumber;

    const indexOfNewPublicKey = indexOfSequenceNumber + sequenceNumberLength;
    signBufferForSignatureUsingPrivateKey
      .set(newPublicKeyBytes, indexOfNewPublicKey);

    const indexOfAppIdHash = indexOfNewPublicKey + newPublicKeyBytes.length;
    signBufferForSignatureUsingPrivateKey.set(appIdBytes, indexOfAppIdHash);

    const indexOfAttestationCert = indexOfAppIdHash + appIdBytes.length;
    signBufferForSignatureUsingPrivateKey
      .set(newAttestationCertBytes, indexOfAttestationCert);

    // Create Signature Using Old Private Key
    const ecdsaOldPrivateKey = generateKey(UTIL_HexToArray(registration.keys.sec));
    const signatureUsingOldPrivateKey = UTIL_JsonSignatureToAsn1(
      ecdsaOldPrivateKey.sign(signBufferForSignatureUsingPrivateKey));

    // Create Signature Using Attestation Private Key
    const lengthOfSignBufferForSignatureUsingAttestationKey =
          signBufferForSignatureUsingPrivateKey.length +
          signatureUsingOldPrivateKey.length;
    let signBufferForSignatureUsingAttestationKey =
        new Uint8Array(lengthOfSignBufferForSignatureUsingAttestationKey);

    signBufferForSignatureUsingAttestationKey
      .set(signBufferForSignatureUsingPrivateKey, 0);
    signBufferForSignatureUsingAttestationKey
      .set(signatureUsingOldPrivateKey,
           signBufferForSignatureUsingPrivateKey.length);

    const ecdsaOldAttestationKey =
          generateKey(UTIL_HexToArray(this.attestationKey));
    const signatureUsingOldAttestationKey = UTIL_JsonSignatureToAsn1(
      ecdsaOldAttestationKey.sign(signBufferForSignatureUsingAttestationKey));

    // Build TransferAccessMessage
    const lengthOfSignatureField = 1;
    const lengthOfTransferAccessMessageData =
          signBufferForSignatureUsingAttestationKey.length +
          signatureUsingOldAttestationKey.length +
          2 * lengthOfSignatureField;
    let transferAccessMessageData =
        new Uint8Array(lengthOfTransferAccessMessageData);

    transferAccessMessageData.set(signBufferForSignatureUsingPrivateKey, 0);

    const indexOfLengthFieldForSignatureUsingOldPrivateKey =
          signBufferForSignatureUsingPrivateKey.length;
    transferAccessMessageData[indexOfLengthFieldForSignatureUsingOldPrivateKey] =
      0xFF & signatureUsingOldPrivateKey.length;

    const indexOfSignatureUsingOldPrivateKey =
          indexOfLengthFieldForSignatureUsingOldPrivateKey +
          lengthOfSignatureField;
    transferAccessMessageData.set(signatureUsingOldPrivateKey,
                                  indexOfSignatureUsingOldPrivateKey);

    const indexOfLengthFieldForSignatureUsingOldAttestationKey =
          indexOfSignatureUsingOldPrivateKey +
          signatureUsingOldPrivateKey.length;
    transferAccessMessageData[indexOfLengthFieldForSignatureUsingOldAttestationKey] = 
      0xFF & signatureUsingOldAttestationKey.length;

    const indexOfSignatureUsingOldAttestationKey =
          indexOfLengthFieldForSignatureUsingOldAttestationKey +
          lengthOfSignatureField;
    transferAccessMessageData
      .set(signatureUsingOldAttestationKey,
           indexOfSignatureUsingOldAttestationKey);
    
    return transferAccessMessageData;
  };


/**
 * Looks up an existing registration by appId and keyHandle.
 * Returns null if not found.
 * @param {string} appIdHash in base64-urlsafe
 * @param {string} keyHandle in base64-urlsafe
 * @return {?SoftTokenRegistration}
 */
SoftTokenProfile.prototype.getRegistration = function(appIdHash, keyHandle) {
  var reg = null;
  for (var i = 0; i < this.registrations.length; ++i) {
    reg = this.registrations[i];
    if (reg.appIdHash == appIdHash && reg.keyHandle == keyHandle)
      return reg;
  }
  return null;
};


/**
 * Looks up an existing registration by appId and keyHandle.
 * Returns null if not found.
 * @param {string} appIdHash in base64-urlsafe
 * @param {string} oldKeyHandle in base64-urlsafe
 * @return {?SoftTokenRegistration}
 */
SoftTokenProfile.prototype.getRegistrationByOldKeyHandle =
  function(appIdHash, oldKeyHandle) {
  var reg = null;
  for (var i = 0; i < this.registrations.length; ++i) {
    reg = this.registrations[i];
    if (reg.appIdHash === appIdHash && reg.oldKeyHandle === oldKeyHandle)
      return reg;
  }
  return null;
};


/**
 * Looks up an existing registration by appId and keyHandle and removes it from
 * stored registrations.
 * Returns true if found
 * Returns false if not found.
 * @param {string} appIdHash in base64-urlsafe
 * @param {string} keyHandle in base64-urlsafe
 * @return {boolean}
 */
SoftTokenProfile.prototype.removeRegistration = function(appIdHash, keyHandle) {
  var reg = null;
  for (var i = 0; i < this.registrations.length; ++i) {
    reg = this.registrations[i];
    if (reg.appIdHash == appIdHash && reg.keyHandle == keyHandle)
      this.registrations.splice(i, 1);
      return true;
  }
  return false;
};


/**
 * Looks up an existing transferAccessChain by appId and keyHandle and
 * pops it out of the transferAccessChains array.
 * Returns null if not found.
 * @param {string} appIdHash in base64-urlsafe
 * @param {string} keyHandle in base64-urlsafe
 * @return {?SoftTokenTransferAccessChain}
 */
SoftTokenProfile.prototype.getTransferAccessChain =
  function(appIdHash, keyHandle) {
    let chain = null;
    for (let i = 0; i < this.transferAccessChains.length; ++i) {
      chain = this.transferAccessChains[i];
      if (chain.registration.appIdHash === appIdHash &&
          chain.originalKeyHandle === keyHandle) {
        return chain;
      }
    }
    return null;
  };


/**
 * Looks up an existing transferAccessChain by matching registration.
 * returns null if not found.
 * @param {!SoftTokenRegistration} registration
 * return {?SoftTokenTransferAccessChain}
 */
SoftTokenProfile.prototype.getTransferAccessChainByRegistration =
  function(registration) {
    let chain = null;
    for (let i = 0; i < this.transferAccessChains.length; ++i) {
      chain = this.transferAccessChains[i];
      if (chain.registration.appIdHash === registration.appIdHash &&
          chain.registration.keyHandle === registration.keyHandle) {
        this.transferAccessChains.splice(i, 1);
        return chain;
      }
    }
    return null;
  };


/**
 * Looks up an existing transferAccessChain by appId and original keyHandle
 * and removes it from the transferAccessChains array.
 * returns false if not found.
 * @param {string} appIdHash in base64-urlsafe
 * @param {string} originalKeyHandle in base64-urlsafe
 * @return {boolean}
 */
SoftTokenProfile.prototype.removeTransferAccessChain =
  function(appIdHash, originalKeyHandle) {
    let chain = null;
    for (let i = 0; i < this.transferAccessChains.length; ++i) {
      chain = this.transferAccessChains[i];
      if (chain.registration.appIdHash === appIdHash &&
          chain.originalKeyHandle === originalKeyHandle) {
        this.transferAccessChains.splice(i, 1);
        return true;
      }
    }
    return false;
  };


/**
 * Looks up an existing transferAccessChain by matching registration
 * and removes it from the transferAccessChains array.
 * returns false if not found.
 * @param {!SoftTokenRegistration} registration
 * return {boolean}
 */
SoftTokenProfile.prototype.removeTransferAccessChainByRegistration =
  function(registration) {
    let chain = null;
    for (let i = 0; i < this.transferAccessChains.length; ++i) {
      chain = this.transferAccessChains[i];
      if (chain.registration.appIdHash === registration.appIdHash &&
          chain.registration.keyHandle === registration.keyHandle) {
        this.transferAccessChains.splice(i, 1);
        return true;
      }
    }
    return false;
  };


/**
 * Looks up an existing transferAccessChain by appId and keyHandle
 * @param {string} appIdHash in base64-urlsafe
 * @param {string} keyHandle in base64-urlsafe
 * @return {boolean}
 */
SoftTokenProfile.prototype.hasMatchingTransferAccessChain =
  function(appIdHash, keyHandle) {
    let chain = null;
    for (let i = 0; i < this.transferAccessChains.length; ++i) {
      chain = this.transferAccessChains[i];
      if (chain.registration.appIdHash === appIdHash &&
          (chain.originalKeyHandle === keyHandle ||
           chain.registration.keyHandle === keyHandle)) {
        this.transferAccessChains.splice(i, 1);
        return true;
      }
    }
    return false;
  };

/**
 * Clears the isBeingTransferredFlag for every stored registration.
 * @return {boolean}
 */
SoftTokenProfile.prototype.clearWaitingOnTransferAccessMessageNumber = function() {
  for (let i = 0; i < this.registrations.length; i++) {
    delete this.registrations[i].waitingOnTransferAccessMessageNumber;
  }
  return true;
};

/**
 * @param {!Object} profile
 * @param {*} request
 * @constructor
 * @implements {RequestHandler}
 */
function SoftTokenEnrollHandler(profile, request) {
  this.profile_ = profile;
  this.request_ = request;
}


/**
 * @param {RequestHandlerCallback} cb Called with the result of the request
 * @return {boolean} Whether this handler could be run.
 */
SoftTokenEnrollHandler.prototype.run = function(cb) {
  console.log('SoftTokenEnrollHandler.run', this.request_);

  var i;

  // First go through signData and see if we already own one of the keyhandles
  for (i = 0; i < this.request_.signData.length; ++i) {
    var sd = this.request_.signData[i];
    if (sd.version != 'U2F_V2')
      continue;
    if (this.profile_.getRegistration(sd.appIdHash, sd.keyHandle)) {
      cb({
        'type': 'enroll_helper_reply',
        'code': DeviceStatusCodes.WRONG_DATA_STATUS
      });
      return true;
    }
  }

  // See if one of the keyhandles is in a transferAccessMessage
  for (i = 0; i < this.request_.signData.length; ++i) {
    let sd = this.request_.signData[i];
    if (sd.version != 'U2F_V2')
      continue;
    if (this.profile_
        .hasMatchingTransferAccessChain(sd.appIdHash, sd.keyHandle)) {
      cb({
        'type': 'enroll_helper_reply',
        'code': DeviceStatusCodes.WRONG_DATA_STATUS
      });
      return true;
    }
  }

  // Not yet registered, look for an enroll challenge with our version
  var challenge;
  for (i = 0; i < this.request_.enrollChallenges.length; ++i) {
    var c = this.request_.enrollChallenges[i];
    if (c.version && c.version == 'U2F_V2') {
      challenge = c;
      break;
    }
  }
  if (!challenge) {
    cb({
      'type': 'enroll_helper_reply',
      'code': DeviceStatusCodes.TIMEOUT_STATUS
    });
    return true;
  }

  // Found a challenge, lets register it
  var keyPair;
  if (SoftTokenHelper.keyPairForTesting) {
    keyPair = SoftTokenHelper.keyPairForTesting;
  } else {
    var tmpEcdsa = generateKey();
    keyPair = {
      sec: UTIL_BytesToHex(tmpEcdsa.getPrivateKey()),
      pub: UTIL_BytesToHex(tmpEcdsa.getPublicKey())
    };
  }
  var registration =
      this.profile_.createRegistration(challenge.appIdHash, keyPair);

  var appIdBytes = new Uint8Array(B64_decode(challenge.appIdHash));
  var challengeBytes = new Uint8Array(B64_decode(challenge.challengeHash));
  var keyHandleBytes = new Uint8Array(B64_decode(registration.keyHandle));
  var publicKeyBytes = UTIL_HexToBytes(registration.keys.pub);

  var signBuf = new Uint8Array(1 + 32 + 32 + keyHandleBytes.length + 65);
  signBuf[0] = 0x00;
  signBuf.set(appIdBytes, 1);
  signBuf.set(challengeBytes, 33);
  signBuf.set(keyHandleBytes, 65);
  signBuf.set(publicKeyBytes, 65 + keyHandleBytes.length);

  // E2E SHA-256 requires a regular Array<number>
  signBuf = Array.prototype.slice.call(signBuf);

  var ecdsa = generateKey(UTIL_HexToArray(this.profile_.attestationKey));
  var signature = UTIL_JsonSignatureToAsn1(ecdsa.sign(signBuf));

  var certBytes = UTIL_HexToBytes(this.profile_.attestationCert);

  var regData = new Uint8Array(1 + 65 + 1 +
      keyHandleBytes.length + certBytes.length + signature.length);

  var offset = 0;
  regData[offset++] = 0x05;
  regData.set(publicKeyBytes, offset);
  offset += publicKeyBytes.length;
  regData[offset++] = keyHandleBytes.length;
  regData.set(keyHandleBytes, offset);
  offset += keyHandleBytes.length;
  regData.set(certBytes, offset);
  offset += certBytes.length;
  regData.set(signature, offset);

  cb({
    'type': 'enroll_helper_reply',
    'code': DeviceStatusCodes.OK_STATUS,
    'version': 'U2F_V2',
    'enrollData': B64_encode(regData)
  });
  return true;
};


/**
 * Closes this handler.
 */
SoftTokenEnrollHandler.prototype.close = function() {
  // No-op
};



/**
 * @param {!Object} profile
 * @param {*} request
 * @constructor
 * @implements {RequestHandler}
 */
function SoftTokenSignHandler(profile, request) {
  this.profile_ = profile;
  this.request_ = request;
}


/**
 * @param {RequestHandlerCallback} cb Called with the result of the request
 * @return {boolean} Whether this handler could be run.
 */
SoftTokenSignHandler.prototype.run = function(cb) {
  console.log('SoftTokenSignHandler.run', this.request_);

  var i;

  // See if we know any of the keyHandles
  var registration, signData = null;
  let keyHandleMatchesStoredRegistration = false;
  for (i = 0; i < this.request_.signData.length; ++i) {
    var sd = this.request_.signData[i];
    if (sd.version != 'U2F_V2')
      continue;
    registration = this.profile_.getRegistration(sd.appIdHash, sd.keyHandle);
    if (registration) {
      signData = sd;
      keyHandleMatchesStoredRegistration = true;
      break;
    }
  }

  
  // See if any of the keyHandles refer to transferAccessMessages
  let transferAccessChain = null;
  let isTransferAccess = false;
  for (i = 0; i< this.request_.signData.length; ++i) {
    let sd = this.request_.signData[i];
    if (sd.version != 'U2F_V2')
      continue;
    transferAccessChain =
      this.profile_.getTransferAccessChain(sd.appIdHash, sd.keyHandle);
    if (transferAccessChain && !keyHandleMatchesStoredRegistration) {
      this.profile_.removeTransferAccessChain(sd.appIdHash, sd.keyHandle);
      signData = sd;
      isTransferAccess = true;
      break;
    }
  }

  if (!signData) {
    cb({
      'type': 'sign_helper_reply',
      'code': DeviceStatusCodes.WRONG_DATA_STATUS
    });
    return true;
  }

  if (isTransferAccess === true) {
    return this.runTransferAccess(cb, transferAccessChain, signData.challengeHash);
  }

  // Increment the counter
  ++registration.counter;

  var signBuffer = new Uint8Array(32 + 1 + 4 + 32);
  signBuffer.set(B64_decode(registration.appIdHash), 0);
  signBuffer[32] = 0x01;  // user presence
  // Sadly, JS TypedArrays are whatever-endian the platform is,
  // so Uint32Array is not at all useful here (or anywhere?),
  // and we must manually pack the counter (big endian as per spec).
  signBuffer[33] = 0xFF & registration.counter >>> 24;
  signBuffer[34] = 0xFF & registration.counter >>> 16;
  signBuffer[35] = 0xFF & registration.counter >>> 8;
  signBuffer[36] = 0xFF & registration.counter;
  signBuffer.set(B64_decode(signData.challengeHash), 37);

  // E2E SHA-256 requires a regular Array<number>
  var signBufferArray = Array.prototype.slice.call(signBuffer);

  var ecdsa = generateKey(UTIL_HexToArray(registration.keys.sec));
  var signature = UTIL_JsonSignatureToAsn1(ecdsa.sign(signBufferArray));

  var signatureData = new Uint8Array(1 + 4 + signature.length);
  // Grab user presence byte and counter from the sign base buffer
  signatureData.set(signBuffer.subarray(32, 37), 0);
  signatureData.set(signature, 5);

  let signHelperReply;
  signHelperReply = {
    'type': 'sign_helper_reply',
    'code': DeviceStatusCodes.OK_STATUS,
    'responseData': {
      'version': 'U2F_V2',
      'appIdHash': registration.appIdHash,
      'challengeHash': signData.challengeHash,
      'keyHandle': registration.keyHandle,
      'signatureData': B64_encode(signatureData)
    }
  };

  cb(signHelperReply);
  return true;
};

/**
 * @param {RequestHandlerCallback} cb Called with the result of the request
 * @param {!SoftTokenTransferAccessChain} transferAccessChain
 * @param {string} challengeHash in base64-urlsafe
 * @return {boolean} Whether this handler could be run.
 */
SoftTokenSignHandler.prototype.runTransferAccess =
  function(cb, transferAccessChain, challengeHash) {
    const controlByteLength = 1;
    const keyHandleLengthFieldLength = 1;
    const counterLength = 4;
    const challengeBytes = new Uint8Array(B64_decode(challengeHash));
    const keyHandleBytes =
          new Uint8Array(B64_decode(transferAccessChain.registration.keyHandle));
    const transferAccessMessageChain =
          transferAccessChain.transferAccessMessageChain;
    const transferAccessMessageChainHash =
          new SHA256().digest(transferAccessMessageChain);
    const lengthOfSignBufferTransferAccessResponse = controlByteLength +
          counterLength +
          challengeBytes.length +
          keyHandleBytes.length +
          transferAccessMessageChainHash.length;
    
    let signBufferTransferAccessResponse =
        new Uint8Array(lengthOfSignBufferTransferAccessResponse);

    const controlByte = 0x03;

    const indexOfControlByte = 0;
    signBufferTransferAccessResponse[indexOfControlByte] = controlByte;

    // Sadly, JS TypedArrays are whatever-endian the platform is,
    // so Uint32Array is not at all useful here (or anywhere?),
    // and we must manually pack the counter (big endian as per spec).
    const indexOfCounter = indexOfControlByte + controlByteLength;
    signBufferTransferAccessResponse[indexOfCounter] =
      0xFF & transferAccessChain.registration.counter >>> 24;
    signBufferTransferAccessResponse[indexOfCounter + 1] =
      0xFF & transferAccessChain.registration.counter >>> 16;
    signBufferTransferAccessResponse[indexOfCounter + 2] =
      0xFF & transferAccessChain.registration.counter >>> 8;
    signBufferTransferAccessResponse[indexOfCounter + 3] =
      0xFF & transferAccessChain.registration.counter;

    const indexOfChallenge = indexOfCounter + counterLength;
    signBufferTransferAccessResponse.set(challengeBytes, indexOfChallenge);

    const indexOfKeyHandle = indexOfChallenge + challengeBytes.length;
    signBufferTransferAccessResponse
      .set(keyHandleBytes, indexOfKeyHandle);

    const indexOfTransferAccessMessageChainHash = indexOfKeyHandle +
          keyHandleBytes.length;
    signBufferTransferAccessResponse
      .set(transferAccessMessageChainHash,
           indexOfTransferAccessMessageChainHash);

    // E2E SHA-256 requires a regular Array<number>
    const signBufferArrayTransferAccessResponse =
          Array.prototype.slice.call(signBufferTransferAccessResponse);

    const ecdsaAttestationKey =
          generateKey(UTIL_HexToArray(this.profile_.attestationKey));
    const signatureTransferAccessResponse =
          UTIL_JsonSignatureToAsn1(
            ecdsaAttestationKey.sign(signBufferArrayTransferAccessResponse));

    const lengthOfTransferAccessResponse = controlByteLength +
          transferAccessMessageChain.length +
          keyHandleLengthFieldLength +
          keyHandleBytes.length +
          counterLength +
          signatureTransferAccessResponse.length;

    let transferAccessResponse =
        new Uint8Array(lengthOfTransferAccessResponse);

    // Build TransferAccessResponse
    const indexOfControlByteTransferAccessResponse = 0;
    transferAccessResponse[indexOfControlByteTransferAccessResponse] =
      controlByte;

    const indexOfTransferAccessMessageChainTransferAccessResponse =
          indexOfControlByteTransferAccessResponse +
          controlByteLength;
    transferAccessResponse
      .set(transferAccessMessageChain,
           indexOfTransferAccessMessageChainTransferAccessResponse);

    const indexOfLengthOfKeyHandleTransferAccessResponse =
          indexOfTransferAccessMessageChainTransferAccessResponse +
          transferAccessMessageChain.length;
    transferAccessResponse[indexOfLengthOfKeyHandleTransferAccessResponse] =
      0xFF & keyHandleBytes.length;

    const indexOfKeyHandleTransferAccessResponse =
          indexOfLengthOfKeyHandleTransferAccessResponse +
          keyHandleLengthFieldLength;
    transferAccessResponse
      .set(keyHandleBytes, indexOfKeyHandleTransferAccessResponse);

    // Sadly, JS TypedArrays are whatever-endian the platform is,
    // so Uint32Array is not at all useful here (or anywhere?),
    // and we must manually pack the counter (big endian as per spec).
    const indexOfCounterTransferAccessResponse =
          indexOfKeyHandleTransferAccessResponse + keyHandleBytes.length;
    transferAccessResponse[indexOfCounterTransferAccessResponse] =
      transferAccessResponse[indexOfCounterTransferAccessResponse] =
      0xFF & transferAccessChain.registration.counter >>> 24;
    transferAccessResponse[indexOfCounterTransferAccessResponse + 1] =
      0xFF & transferAccessChain.registration.counter >>> 16;
    transferAccessResponse[indexOfCounterTransferAccessResponse + 2] =
      0xFF & transferAccessChain.registration.counter >>> 8;
    transferAccessResponse[indexOfCounterTransferAccessResponse + 3] =
      0xFF & transferAccessChain.registration.counter;

    const indexOfSignatureTransferAccessResponse =
          indexOfCounterTransferAccessResponse + counterLength;
    transferAccessResponse
      .set(signatureTransferAccessResponse,
           indexOfSignatureTransferAccessResponse);

    let signHelperReply;
    signHelperReply = {
      'type': 'transfer_access_helper_reply',
      'code': DeviceStatusCodes.OK_STATUS,
      'responseData': {
        'version': 'U2F_V2',
        'appIdHash': transferAccessChain.registration.appIdHash,
        'challengeHash': challengeHash,
        'keyHandle': transferAccessChain.registration.keyHandle,
        'signatureData': B64_encode(transferAccessResponse)
      }
    };

  cb(signHelperReply);
  return true;
};


/**
 * Closes this handler.
 */
SoftTokenSignHandler.prototype.close = function() {
  // No-op
};


/**
 * @param {!Object} profile
 * @param {*} request
 * @constructor
 * @implements {RequestHandler}
 */
function SoftTokenTransferAccessHandler(profile, request) {
  this.profile_ = profile;
  this.request_ = request;
}

/**
 * @param {RequestHandlerCallback} cb Called with the result of the request
 * @return {boolean} Whether this handler could be run.
 */
SoftTokenTransferAccessHandler.prototype.run = function(cb) {
  console.log('SoftTokenEnrollHandler.run', this.request_);
  let wrongDataStatus = {
    type: 'transfer_access_client_message',
    code: DeviceStatusCodes.WRONG_DATA_STATUS
  };

  if (this.request_.type !== "transfer_access_client_message" ||
      typeof this.request_.messageNumber !== "number" ||
      this.request_.messageNumber < 1 ||
      this.request_.messageNumber > 4) {
    cb(wrongDataStatus);
    return true;
  }

  if (this.request_.messageNumber === 1) {
    let transferAccessClientMessage2 = {
      type: "transfer_access_client_message",
      code: DeviceStatusCodes.OK_STATUS,
      messageNumber: 2,
      attestationCert: this.profile_.attestationCert,
      newPubKeys: []
    };

    for (let i = 0; i < this.request_.transfers.length; i++) {
      let transfer = this.request_.transfers[i];

      if (transfer.version != 'U2F_V2') {
        transferAccessClientMessage2 = wrongDataStatus;
        continue;
      }

      let keyPair;
      if (SoftTokenHelper.keyPairForTesting) {
        keyPair = SoftTokenHelper.keyPairForTesting;
      } else {
        var tmpEcdsa = generateKey();
        keyPair = {
          sec: UTIL_BytesToHex(tmpEcdsa.getPrivateKey()),
          pub: UTIL_BytesToHex(tmpEcdsa.getPublicKey())
        };
      }
      var registration =
        this.profile_.createRegistration(transfer.appIdHash, keyPair);
      registration.waitingOnTransferAccessMessageNumber = 3;
      registration.oldKeyHandle = transfer.keyHandle;
      transferAccessClientMessage2.newPubKeys.push({
        appIdHash: transfer.appIdHash,
        keyHandle: transfer.keyHandle,
        pubKey: registration.keys.pub
      });
    }

    cb(transferAccessClientMessage2);
    return true;
  }

  if (this.request_.messageNumber === 2) {
    let newAttestationCert = this.request_.attestationCert;

    let transferAccessClientMessage3 = {
      type: "transfer_access_client_message",
      code: DeviceStatusCodes.OK_STATUS,
      messageNumber: 3,
      transferAccessChains: []
    };

    for (let i = 0; i < this.request_.newPubKeys.length; i++) {
      let newPubKeyObject = this.request_.newPubKeys[i];
      let newPubKey = newPubKeyObject.pubKey;
      let registration =
        this.profile_.getRegistration(newPubKeyObject.appIdHash,
                                      newPubKeyObject.keyHandle);

      if (registration !== null &&
          registration.waitingOnTransferAccessMessageNumber === 2) {
        let transferAccessChain =
          this.profile_.getTransferAccessChainByRegistration(registration);

        let sequenceNumber = 1;
        let transferAccessMessageChain = [];
        let originalKeyHandle = registration.keyHandle;

        if (transferAccessChain !== null) {
          if (typeof transferAccessChain.originalKeyHandle === "string") {
            originalKeyHandle = transferAccessChain.originalKeyHandle;
          }

          if (transferAccessChain.transferAccessMessageChain.constructor ===
              Uint8Array) {
            transferAccessMessageChain =
              transferAccessChain.transferAccessMessageChain;
            sequenceNumber += transferAccessMessageChain[0];
          }
        };

        let transferAccessMessage =
          this.profile_.buildTransferAccessMessage(sequenceNumber,
                                                   newPubKey,
                                                   registration,
                                                   newAttestationCert);

        let newTransferAccessMessageChain =
          new Uint8Array(transferAccessMessage.length +
                         transferAccessMessageChain.length);
        newTransferAccessMessageChain.set(transferAccessMessage, 0);
        if (transferAccessMessageChain.length > 0) {
          newTransferAccessMessageChain.set(transferAccessMessageChain,
                                            transferAccessMessage.length);          
        }

        let returningTransferAccessMessageChain;
        returningTransferAccessMessageChain = {
          appIdHash: registration.appIdHash,
          keyHandle: registration.keyHandle,
          originalKeyHandle: originalKeyHandle,
          transferAccessMessageChain: newTransferAccessMessageChain
        };

        transferAccessClientMessage3.transferAccessChains
          .push(returningTransferAccessMessageChain);

        registration.waitingOnTransferAccessMessageNumber = 4;
      }
    }

    cb(transferAccessClientMessage3);
    return true;
  }

  if (this.request_.messageNumber === 3) {
    let transferAccessClientMessage4 = {
      type: "transfer_access_client_message",
      code: DeviceStatusCodes.OK_STATUS,
      messageNumber: 4,
      acks: []
    };

    for (let i = 0; i < this.request_.transferAccessChains.length; ++i) {
      // Store the transfer access message
      let transferAccessChain = this.request_.transferAccessChains[i];
      let transferAccessMessageChain =
        transferAccessChain.transferAccessMessageChain;
      let appIdHash = transferAccessChain.appIdHash;
      let keyHandle = transferAccessChain.keyHandle;
      let originalKeyHandle = transferAccessChain.originalKeyHandle;
      let registration = this.profile_.getRegistrationByOldKeyHandle(appIdHash, keyHandle);
      this.profile_.createTransferAccessChain(registration,
                                              originalKeyHandle,
                                              transferAccessMessageChain);

      let ack = {
        appIdHash: appIdHash,
        keyHandle: keyHandle
      };

      transferAccessClientMessage4.acks.push(ack);
    }

    cb(transferAccessClientMessage4);
    return true;
  }

  if (this.request_.messageNumber === 4) {
  // TODO: What do we do with the callback?
    for (let i = 0; i < this.request_.acks.length; i++) {
      let ack = this.request_.acks[i];
      let reg = this.profile_.getRegistration(ack.appIdHash, ack.keyHandle);
      if (reg.waitingOnTransferAccessMessageNumber === 4) {
        this.profile_.removeRegistration(ack.appIdHash, ack.keyHandle);
        this.profile_.removeTransferAccessChainByRegistration(reg);
      }
    }
    
    this.profile_.clearWaitingOnTransferAccessMessageNumber();
    return true;
  }

  return false;
};

/**
 * Closes this handler.
 */
SoftTokenTransferAccessHandler.prototype.close = function() {
  this.profile_.clearWaitingOnTransferAccessMessageNumber();
};
