describe("Spec testing", function() {
  var pubKey, secKey;
  var appIdHash, keyHandle, challengeHash, version, timeoutSeconds;
  var enrollChallenges, signData;
  var softTokenProfile, softTokenHelper;
  var softTokenSignHandler, softTokenEnrollHandler;
  var enrollHelperRequest, signHelperRequest;
  var expectedEnrollResponseAlreadyMatchingKeyHandle;
  var originalKeyHandle, newKeyHandle, newPubKey, newSecKey;
  var exampleRegistration, exampleNewRegistration;
  var exampleTransferAccessChain, exampleTransferAccessChain2;
  var expectedSoftTokenSignResponseNoMatchingKey;
  var expectedSoftTokenSignResponseMatchingKey;

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

    softTokenSignHandler =
      new SoftTokenSignHandler(softTokenProfile, signHelperRequest);
    softTokenEnrollHandler =
      new SoftTokenEnrollHandler(softTokenProfile, enrollHelperRequest);

    expectedEnrollResponseAlreadyMatchingKeyHandle = {
      type: 'enroll_helper_reply',
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
    var expectedRegistration;

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
      var softTokenEnrollResponse = softTokenEnrollHandler.run(this.callback);
      expect(softTokenEnrollResponse).toBe(true);
      expect(softTokenProfile.registrations).toEqual([expectedRegistration]);
    });

    it("should send WRONG_DATA_STATUS if we already own one of the keyhandles",
       function() {
         softTokenProfile.registrations = [exampleRegistration];
         var softTokenEnrollResponse = softTokenEnrollHandler.run(this.callback);
         expect(softTokenEnrollResponse).toBe(true);
         expect(this.callback)
           .toHaveBeenCalledWith(expectedEnrollResponseAlreadyMatchingKeyHandle);
    });
  });

  describe("Signing", function() {
    it("should fail if no key exists", function() {
      var softTokenSignResponse = softTokenSignHandler.run(this.callback);
      expect(softTokenSignResponse).toBe(true);
      expect(this.callback)
        .toHaveBeenCalledWith(expectedSoftTokenSignResponseNoMatchingKey);
    });

    it("should fail if a different key exists", function() {
      var softTokenEnrollResponse = softTokenEnrollHandler.run(this.callback);
      expect(softTokenEnrollResponse).toBe(true);

      // Check a different key
      var softTokenSignResponse = softTokenSignHandler.run(this.callback);
      expect(softTokenSignResponse).toBe(true);
      expect(this.callback)
        .toHaveBeenCalledWith(expectedSoftTokenSignResponseNoMatchingKey);
    });

    it("should succeed if a matching key does exist", function() {
      softTokenProfile.registrations = [exampleRegistration];
      var softTokenSignResponse = softTokenSignHandler.run(this.callback);
      expect(softTokenSignResponse).toBe(true);
      expect(this.callback)
        .toHaveBeenCalledWith(expectedSoftTokenSignResponseMatchingKey);
    });
  });

  describe("TransferAccess", function() {
    var signHelperRequestForTransferAccess;
    var softTokenSignHandlerForTransferAccess;
    var expectedSoftTokenSignResponseTransferAccess;

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
    });

    // softokkenhelper to softokkenhelper communication
    it("should generate key handle and public key when asked", function() {
    });

    it("should return an attestation cert and <key handle, pubkey> pair in " + 
       "response", function() {
       });
    
    it("should create a transfer access message and send it to the other " +
       "profile", function() {
       });

    it("should add to a chain if one is passed to it", function() {
    });

    it("should generate and return a transferAccessMessage", function() {
    });

    it("should return a chain if it has a chain stored", function() {
    });

    it("should send an ack", function() {
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
         var softTokenSignResponse = softTokenSignHandler.run(this.callback);
         expect(softTokenSignResponse).toBe(true);
         expect(this.callback)
           .toHaveBeenCalledWith(expectedSoftTokenSignResponseMatchingKey);
       });

    it("should sign in if the key handle matches a stored credential and " +
       "transferAccessMessages exist", function() {
         softTokenProfile.registrations = [exampleRegistration];
         softTokenProfile.transferAccessChains = [exampleTransferAccessChain];
         var softTokenSignResponse = softTokenSignHandler.run(this.callback);
         expect(softTokenSignResponse).toBe(true);
         expect(this.callback)
           .toHaveBeenCalledWith(expectedSoftTokenSignResponseMatchingKey);
       });

    it("should fail if no matching key or transferAccessMessage exists",
       function() {
         softTokenProfile.transferAccessChains = [exampleTransferAccessChain];
         var softTokenSignResponse = softTokenSignHandler.run(this.callback);
         expect(softTokenSignResponse).toBe(true);
         expect(this.callback)
           .toHaveBeenCalledWith(expectedSoftTokenSignResponseNoMatchingKey);
    });

    it("should return a transferAccessResponse if a transferAccessMessage is " +
       "stored instead of a normal key", function() {
         softTokenProfile.transferAccessChains = [
           exampleTransferAccessChain, exampleTransferAccessChain2
         ];
         var softTokenSignResponse = softTokenSignHandlerForTransferAccess
             .run(this.callback);
         expect(softTokenSignResponse).toBe(true);
         expect(this.callback)
           .toHaveBeenCalledWith(expectedSoftTokenSignResponseTransferAccess);
       });

    it("should have normal credentials after delivering the " +
       "transferAccessMessage to the server successfully", function() {
         softTokenProfile.transferAccessChains = [exampleTransferAccessChain];
         var softTokenSignResponse = softTokenSignHandlerForTransferAccess
             .run(this.callback);
         expect(softTokenProfile.transferAccessChains).toEqual([]);
         expect(softTokenProfile.registrations).toEqual(exampleRegistration);
       });

    it("should send WRONG_DATA_STATUS if one of the key handles to be " +
       "enrolled is in a transferAccessMessage", function() {
         softTokenProfile.transferAccessChains = [
           exampleTransferAccessChain, exampleTransferAccessChain2
         ];
         var softTokenEnrollResponse = softTokenEnrollHandler.run(this.callback);
         expect(softTokenEnrollResponse).toBe(true);
         expect(this.callback)
           .toHaveBeenCalledWith(expectedEnrollResponseAlreadyMatchingKeyHandle);
       });
  });
});
