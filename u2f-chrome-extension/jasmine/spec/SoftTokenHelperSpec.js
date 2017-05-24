describe("Spec testing", function() {
  let pubKey, secKey;
  let appIdHash, keyHandle, challengeHash, version, timeoutSeconds;
  let enrollChallenges, signData;
  let softTokenProfile, softTokenHelper;
  let softTokenSignHandler, softTokenEnrollHandler,
      softTokenTransferAccessHandler;
  let enrollHelperRequest, signHelperRequest;
  let transferAccessClientMessage,
      transferAccessClientMessage1,
      transferAccessClientMessage2,
      transferAccessClientMessage3,
      transferAccessClientMessage4;
  let expectedEnrollResponseAlreadyMatchingKeyHandle;
  let expectedTransferAccessWrongDataStatus;
  let originalKeyHandle, newKeyHandle, newPubKey, newSecKey;
  let exampleRegistration, exampleNewRegistration;
  let exampleTransferAccessChain, exampleTransferAccessChain2;
  let expectedSoftTokenSignResponseNoMatchingKey;
  let expectedSoftTokenSignResponseMatchingKey;

  beforeEach(function() {
    pubKey =
      '041155B2F73ABECCD83986C65AAC0D0BA709762AF2194DA800851026BC828E39' +
      'C069FF8B40F765CD6E36FF164CD31CB96EA7D4326A3C635B3BCDB6AA45E2FEF5' +
      'CE';
    secKey =
      '3C0D26EFA654915BAF619FD94E37084F4024CA3ED52438A2837D9ACB510051C0';
    timeoutSeconds = 600;
    appIdHash = "BaIGvIRlYOG5Dg8y8EKjFdr_4O22_4pcXXoZ7DSuiQk";
    challengeHash = "ckZFHmew8qS78m90y-jC97JEMqNIqd4E49w4DfdFTe8";
    version = "U2F_V2";
    keyHandle = "keyHandle";
    newKeyHandle = "newKeyHandle";
    originalKeyHandle = "originalKeyHandle";
    newPubKey =
      '04D5C8C81E85709411405485107C9342D0A410B8628ADFB6D2C24CDAF5AF4D0A' +
      '285E5B5F240B902B1E8AC6F88474B548DBD4CFAC6D81F73C2517AB2024DBFC8B' +
      '4B';
    newSecKey =
      '8B99CACBA3B76E9E526EAD8B177F7331DC5A1B39E0B5BC02BB00C2E16596A14D';
    enrollChallenges = [
      {
        appIdHash: appIdHash,
        challengeHash: challengeHash,
        version: version
      }
    ];
    signData = [
      {
        version: version,
        appIdHash: appIdHash,
        challengeHash: challengeHash,
        keyHandle: keyHandle
      }
    ];

    softTokenProfile = new SoftTokenProfile();
    inherits(SoftTokenHelper, GenericRequestHelper);
    softTokenHelper = new SoftTokenHelper(softTokenProfile);

    enrollHelperRequest = {
      type: "enroll_helper_request",
      enrollChallenges: enrollChallenges,
      signData: signData,
      timeoutSeconds: timeoutSeconds
    };

    signHelperRequest = {
      type: "sign_helper_request",
      timeoutSeconds: timeoutSeconds,
      signData: signData
    };

    transferAccessClientMessage1 = {
      type: "transfer_access_client_message",
      code: DeviceStatusCodes.OK_STATUS,
      messageNumber: 1,
      transfers: [
        {
          version: version,
          appIdHash: appIdHash,
          keyHandle: keyHandle
        }
      ]
    };

    transferAccessClientMessage2 = {
      type: "transfer_access_client_message",
      code: DeviceStatusCodes.OK_STATUS,
      messageNumber: 2,
      attestationCert: softTokenProfile.attestationCert,
      newPubKeys: [
        {
          appIdHash: appIdHash,
          keyHandle: keyHandle,
          pubKey: newPubKey
        }
      ]
    };

    transferAccessClientMessage3 = {
      type: "transfer_access_client_message",
      code: DeviceStatusCodes.OK_STATUS,
      messageNumber: 3,
      transferAccessChains: [
        {
          appIdHash: appIdHash,
          keyHandle: keyHandle,
          originalKeyHandle: originalKeyHandle,
          transferAccessMessageChain: "transferAccessChain"
        }
      ]
    };

    transferAccessClientMessage4 = {
      type: "transfer_access_client_message",
      code: DeviceStatusCodes.OK_STATUS,
      messageNumber: 4,
      acks: [
        {
          appIdHash: appIdHash,
          keyHandle: keyHandle
        }
      ]
    };

    transferAccessClientMessage = transferAccessClientMessage4;
    
    softTokenSignHandler =
      new SoftTokenSignHandler(softTokenProfile, signHelperRequest);
    softTokenEnrollHandler =
      new SoftTokenEnrollHandler(softTokenProfile, enrollHelperRequest);
    softTokenTransferAccessHandler =
      new SoftTokenTransferAccessHandler(softTokenProfile,
                                         transferAccessClientMessage);

    expectedEnrollResponseAlreadyMatchingKeyHandle = {
      type: 'enroll_helper_reply',
      code: DeviceStatusCodes.WRONG_DATA_STATUS
    };

    expectedTransferAccessWrongDataStatus = {
      type: "transfer_access_client_message",
      code: DeviceStatusCodes.WRONG_DATA_STATUS
    };

    exampleRegistration = {
      appIdHash: appIdHash,
      keyHandle: keyHandle,
      keys: {
        sec: secKey,
        pub: pubKey
      },
      counter: 1
    };

    exampleNewRegistration = {
      appIdHash: appIdHash,
      keyHandle: newKeyHandle,
      keys: {
        sec: newSecKey,
        pub: newPubKey
      },
      counter: 1
    };

    exampleTransferAccessChain = {
      registration: exampleRegistration,
      originalKeyHandle: originalKeyHandle,
      transferAccessMessageChain: "Example TransferAccessMessageChain"
    };

    exampleTransferAccessChain2 = {
      registration: exampleNewRegistration,
      originalKeyHandle: keyHandle,
      transferAccessMessageChain: "Example TransferAccessMessageChain"
    };

    expectedSoftTokenSignResponseNoMatchingKey = {
      type: 'sign_helper_reply',
      code: DeviceStatusCodes.WRONG_DATA_STATUS
    };

    expectedSoftTokenSignResponseMatchingKey = {
      type: 'sign_helper_reply',
      code: DeviceStatusCodes.OK_STATUS,
      responseData: {
        version: version,
        appIdHash: appIdHash,
        challengeHash: challengeHash,
        keyHandle: keyHandle,
        signatureData: jasmine.any(String)
      }
    };

    this.callback = function (input) { //Do nothing
    };
    spyOn(this, 'callback');
  });

  describe("Registration", function() {
    let expectedRegistration;

    beforeEach(function() {
      expectedRegistration = {
        appIdHash: appIdHash,
        keyHandle: jasmine.any(String),
        keys: {
          sec: jasmine.any(String),
          pub: jasmine.any(String)
        },
        counter: 1
      };
    });

    it("should have no keys registered initially", function() {
      expect(softTokenProfile.registrations).toEqual([]);
    });

    it("should register be able to register a new key", function() {
      let softTokenEnrollResponse = softTokenEnrollHandler.run(this.callback);
      expect(softTokenEnrollResponse).toBe(true);
      expect(softTokenProfile.registrations).toEqual([expectedRegistration]);
    });

    it("should send WRONG_DATA_STATUS if we already own one of the keyhandles",
       function() {
         softTokenProfile.registrations = [exampleRegistration];
         let softTokenEnrollResponse = softTokenEnrollHandler.run(this.callback);
         expect(softTokenEnrollResponse).toBe(true);
         expect(this.callback)
           .toHaveBeenCalledWith(expectedEnrollResponseAlreadyMatchingKeyHandle);
       });
  });

  describe("Signing", function() {
    it("should fail if no key exists", function() {
      let softTokenSignResponse = softTokenSignHandler.run(this.callback);
      expect(softTokenSignResponse).toBe(true);
      expect(this.callback)
        .toHaveBeenCalledWith(expectedSoftTokenSignResponseNoMatchingKey);
    });

    it("should fail if a different key exists", function() {
      let softTokenEnrollResponse = softTokenEnrollHandler.run(this.callback);
      expect(softTokenEnrollResponse).toBe(true);

      // Check a different key
      let softTokenSignResponse = softTokenSignHandler.run(this.callback);
      expect(softTokenSignResponse).toBe(true);
      expect(this.callback)
        .toHaveBeenCalledWith(expectedSoftTokenSignResponseNoMatchingKey);
    });

    it("should succeed if a matching key does exist", function() {
      softTokenProfile.registrations = [exampleRegistration];
      let softTokenSignResponse = softTokenSignHandler.run(this.callback);
      expect(softTokenSignResponse).toBe(true);
      expect(this.callback)
        .toHaveBeenCalledWith(expectedSoftTokenSignResponseMatchingKey);
    });
  });

  describe("TransferAccess", function() {
    let signHelperRequestForTransferAccess;
    let softTokenSignHandlerForTransferAccess;
    let expectedSoftTokenSignResponseTransferAccess;
    let expectedTransferAccessClientMessage3NoMatchingKeys,
        expectedTransferAccessClientMessage3NoExistingChain,
        expectedTransferAccessClientMessage3ExistingChain;

    beforeEach(function() {
      signHelperRequestForTransferAccess = {
        type: "sign_helper_request",
        timeoutSeconds: timeoutSeconds,
        signData: [
          {
            version: version,
            appIdHash: appIdHash,
            challengeHash: challengeHash,
            keyHandle: originalKeyHandle
          }
        ]
      };

      softTokenSignHandlerForTransferAccess =
        new SoftTokenSignHandler(softTokenProfile,
                                 signHelperRequestForTransferAccess);

      expectedSoftTokenSignResponseTransferAccess = {
        type: "transfer_access_helper_reply",
        code: DeviceStatusCodes.OK_STATUS,
        responseData: {
          version: version,
          appIdHash: appIdHash,
          challengeHash: challengeHash,
          keyHandle: keyHandle,
          signatureData: jasmine.any(String)
        }
      };

      expectedTransferAccessClientMessage3NoMatchingKeys = {
        type: "transfer_access_client_message",
        code: DeviceStatusCodes.OK_STATUS,
        messageNumber: 3,
        transferAccessChains: []
      };

      expectedTransferAccessClientMessage3NoExistingChain = {
        type: "transfer_access_client_message",
        code: DeviceStatusCodes.OK_STATUS,
        messageNumber: 3,
        transferAccessChains: [
          {
            appIdHash: appIdHash,
            keyHandle: keyHandle,
            originalKeyHandle: keyHandle,
            transferAccessMessageChain: jasmine.any(Uint8Array)
          }
        ]
      };

      expectedTransferAccessClientMessage3ExistingChain = {
        type: "transfer_access_client_message",
        code: DeviceStatusCodes.OK_STATUS,
        messageNumber: 3,
        transferAccessChains: [
          {
            appIdHash: appIdHash,
            keyHandle: keyHandle,
            originalKeyHandle: originalKeyHandle,
            transferAccessMessageChain: jasmine.any(Uint8Array)
          }
        ]
      };
    });

    // softokkenhelper to softokkenhelper communication
    it("should return WRONG_DATA_STATUS if the message is not valid",
       function() {
         transferAccessClientMessage1.messageNumber = 0;
         softTokenTransferAccessHandler.request_ = transferAccessClientMessage1;
         let softTokenTransferAccessResponse =
             softTokenTransferAccessHandler.run(this.callback);
         expect(softTokenTransferAccessResponse).toBe(true);
         expect(this.callback)
           .toHaveBeenCalledWith(expectedTransferAccessWrongDataStatus);
         transferAccessClientMessage1.messageNumber = -1;
         softTokenTransferAccessHandler.request_ = transferAccessClientMessage1;
         softTokenTransferAccessResponse =
             softTokenTransferAccessHandler.run(this.callback);
         expect(softTokenTransferAccessResponse).toBe(true);
         expect(this.callback)
           .toHaveBeenCalledWith(expectedTransferAccessWrongDataStatus);
         transferAccessClientMessage1.messageNumber = 5;
         softTokenTransferAccessHandler.request_ = transferAccessClientMessage1;
         softTokenTransferAccessResponse =
             softTokenTransferAccessHandler.run(this.callback);
         expect(softTokenTransferAccessResponse).toBe(true);
         expect(this.callback)
           .toHaveBeenCalledWith(expectedTransferAccessWrongDataStatus);
         transferAccessClientMessage1.messageNumber = 1;
         transferAccessClientMessage1.type = "something else";
         softTokenTransferAccessHandler.request_ = transferAccessClientMessage1;
         softTokenTransferAccessResponse =
             softTokenTransferAccessHandler.run(this.callback);
         expect(softTokenTransferAccessResponse).toBe(true);
         expect(this.callback)
           .toHaveBeenCalledWith(expectedTransferAccessWrongDataStatus);
       });

    it("should initiate a transfer of access by sending " +
       "[versionNum, appId, keyHandle] for each account to be transferred",
       function() {
         // TODO: All
         let softTokenTransferAccessResponse =
             softTokenProfile.runTransferAccess();
       });

    it("should initiate a transfer of access by sending " +
       "[versionNum, appId, keyHandle] for each account to be transferred." +
       "It should not send keys that aren't indicated",
       function() {
         // TODO: all
         let softTokenTransferAccessResponse =
             softTokenProfile.runTransferAccess();
       });

    it("should return an attestation cert and <key handle, pubkey> pair in " +
       "response", function() {
         softTokenTransferAccessHandler.request_ = transferAccessClientMessage1;
         let softTokenTransferAccessResponse =
             softTokenTransferAccessHandler.run(this.callback);
         expect(softTokenTransferAccessResponse).toBe(true);
         expect(softTokenProfile.registrations).not.toBe([]);
         expect(
           softTokenProfile.registrations[0].waitingOnTransferAccessMessageNumber)
           .toBe(3);
         transferAccessClientMessage2.newPubKeys[0].keyHandle =
           jasmine.any(String);
         transferAccessClientMessage2.newPubKeys[0].pubKey =
           jasmine.any(String);
         expect(this.callback)
           .toHaveBeenCalledWith(transferAccessClientMessage2);
       });
    
    it("should create a transfer access message and send it to the other " +
       "profile", function() {
         exampleRegistration.waitingOnTransferAccessMessageNumber = 2;
         softTokenProfile.registrations = [exampleRegistration];
         softTokenTransferAccessHandler.request_ = transferAccessClientMessage2;
         let softTokenTransferAccessResponse =
             softTokenTransferAccessHandler.run(this.callback);
         expect(softTokenTransferAccessResponse).toBe(true);
         expect(this.callback)
           .toHaveBeenCalledWith(expectedTransferAccessClientMessage3NoExistingChain);
       });

    it("should not create a transfer access message when the appID and " +
       "keyHandle do not match", function() {
         exampleNewRegistration.waitingOnTransferAccessMessageNumber = 2;
         softTokenProfile.registrations = [exampleNewRegistration];
         softTokenTransferAccessHandler.request_ = transferAccessClientMessage2;
         let softTokenTransferAccessResponse =
             softTokenTransferAccessHandler.run(this.callback);
         expect(softTokenTransferAccessResponse).toBe(true);
         expect(this.callback)
           .toHaveBeenCalledWith(expectedTransferAccessClientMessage3NoMatchingKeys);
       });

    // TODO: Is this sufficient? It doesn't test the transferAccessMessageChain.
    it("should add to a chain if one already exists", function() {
      exampleRegistration.waitingOnTransferAccessMessageNumber = 2;
      softTokenProfile.registrations = [exampleRegistration];
      softTokenProfile.transferAccessChains = [exampleTransferAccessChain];
      softTokenTransferAccessHandler.request_ = transferAccessClientMessage2;
      let softTokenTransferAccessResponse =
        softTokenTransferAccessHandler.run(this.callback);
      expect(softTokenTransferAccessResponse).toBe(true);
      expect(this.callback)
        .toHaveBeenCalledWith(expectedTransferAccessClientMessage3ExistingChain);
    });

    // TODO: Check responses when messages are empty or don't contain enough data

    it("should generate and return a transferAccessMessage", function() {
    });

    it("should return a chain if it has a chain stored", function() {
    });

    // TODO: should store the transfer access message and return an ack.
    it("should send an ack", function() {
      softTokenTransferAccessHandler.request_ = transferAccessClientMessage3;
      let softTokenTransferAccessResponse =
        softTokenTransferAccessHandler.run(this.callback);
      expect(softTokenTransferAccessResponse).toBe(true);
      expect(this.callback).toHaveBeenCalledWith(transferAccessClientMessage4);
    });

    it("should delete keys upon receiving an ack", function() {
      exampleRegistration.waitingOnTransferAccessMessageNumber = 4;
      softTokenProfile.registrations = [exampleRegistration];
      softTokenProfile.transferAccessChains = [exampleTransferAccessChain];
      let softTokenTransferAccessResponse =
          softTokenTransferAccessHandler.run(this.callback);
      expect(softTokenTransferAccessResponse).toBe(true);
      expect(softTokenProfile.registrations).toEqual([]);
      expect(softTokenProfile.transferAccessChains).toEqual([]);
    });

    it("should not delete keys upon receiving an ack if those keys haven't " +
       "been transferred", function() {
         softTokenProfile.registrations = [exampleRegistration];
         let softTokenTransferAccessResponse =
             softTokenTransferAccessHandler.run(this.callback);
         expect(softTokenTransferAccessResponse).toBe(true);
         expect(softTokenProfile.registrations).toEqual([exampleRegistration]);
       });

    it("should be able to transfer access to multiple accounts on the same " +
       "domain", function() {
       });

    it("should be able to transfer access to multiple accounts on different " +
       "domains", function() {
       });

    // softokkenhelper to server communication
    it("should sign in if the key handle matches a stored credential and a " +
       "transferAccessMessage is stored with the same key handle", function() {
         exampleTransferAccessChain.originalKeyHandle = keyHandle;
         softTokenProfile.registrations = [exampleRegistration];
         softTokenProfile.transferAccessChains = [exampleTransferAccessChain];
         expect(softTokenProfile.transferAccessChains[0].originalKeyHandle)
           .toEqual(keyHandle);
         expect(softTokenProfile.registrations[0].keyHandle)
           .toEqual(keyHandle);
         let softTokenSignResponse = softTokenSignHandler.run(this.callback);
         expect(softTokenSignResponse).toBe(true);
         expect(this.callback)
           .toHaveBeenCalledWith(expectedSoftTokenSignResponseMatchingKey);
       });

    it("should sign in if the key handle matches a stored credential and " +
       "transferAccessMessages exist", function() {
         softTokenProfile.registrations = [exampleRegistration];
         softTokenProfile.transferAccessChains = [exampleTransferAccessChain];
         let softTokenSignResponse = softTokenSignHandler.run(this.callback);
         expect(softTokenSignResponse).toBe(true);
         expect(this.callback)
           .toHaveBeenCalledWith(expectedSoftTokenSignResponseMatchingKey);
       });

    it("should fail if no matching key or transferAccessMessage exists",
       function() {
         softTokenProfile.transferAccessChains = [exampleTransferAccessChain];
         let softTokenSignResponse = softTokenSignHandler.run(this.callback);
         expect(softTokenSignResponse).toBe(true);
         expect(this.callback)
           .toHaveBeenCalledWith(expectedSoftTokenSignResponseNoMatchingKey);
       });

    it("should return a transferAccessResponse if a transferAccessMessage is " +
       "stored instead of a normal key", function() {
         softTokenProfile.transferAccessChains = [
           exampleTransferAccessChain, exampleTransferAccessChain2
         ];
         let softTokenSignResponse = softTokenSignHandlerForTransferAccess
             .run(this.callback);
         expect(softTokenSignResponse).toBe(true);
         expect(this.callback)
           .toHaveBeenCalledWith(expectedSoftTokenSignResponseTransferAccess);
       });

    it("should have normal credentials after delivering the " +
       "transferAccessMessage to the server successfully", function() {
         softTokenProfile.registrations = [exampleRegistration];
         softTokenProfile.transferAccessChains = [exampleTransferAccessChain];
         let softTokenSignResponse = softTokenSignHandlerForTransferAccess
             .run(this.callback);
         expect(softTokenSignResponse).toBe(true);
         expect(softTokenProfile.transferAccessChains).toEqual([]);
         expect(softTokenProfile.getRegistration(appIdHash, keyHandle))
           .toEqual(exampleRegistration);
       });

    it("should send WRONG_DATA_STATUS if one of the key handles to be " +
       "enrolled is in a transferAccessMessage", function() {
         softTokenProfile.transferAccessChains = [
           exampleTransferAccessChain, exampleTransferAccessChain2
         ];
         let softTokenEnrollResponse = softTokenEnrollHandler.run(this.callback);
         expect(softTokenEnrollResponse).toBe(true);
         expect(this.callback)
           .toHaveBeenCalledWith(expectedEnrollResponseAlreadyMatchingKeyHandle);
       });
  });
});
