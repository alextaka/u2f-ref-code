// Copyright 2014 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package com.google.u2f.codec;

import static org.junit.Assert.*;

import org.junit.Test;

import com.google.u2f.TestVectors;
import com.google.u2f.U2FException;
import com.google.u2f.key.UserPresenceVerifier;
import com.google.u2f.key.messages.AuthenticateRequest;
import com.google.u2f.key.messages.AuthenticateResponse;
import com.google.u2f.key.messages.RegisterRequest;
import com.google.u2f.key.messages.RegisterResponse;
import com.google.u2f.key.messages.TransferAccessMessage;
import com.google.u2f.key.messages.TransferAccessResponse;
import com.google.u2f.server.Crypto;
import com.google.u2f.server.impl.BouncyCastleCrypto;

import static com.google.u2f.TestUtils.computeSha256;

public class RawCodecTest extends TestVectors {
  private static final int INITIAL_COUNTER = 0;
  private final Crypto crypto = new BouncyCastleCrypto();

  @Test
  public void testEncodeRegisterRequest() throws Exception {
    RegisterRequest registerRequest = new RegisterRequest(APP_ID_ENROLL_SHA256,
        BROWSER_DATA_ENROLL_SHA256);

    byte[] encodedBytes = RawMessageCodec.encodeRegisterRequest(registerRequest);

    assertArrayEquals(REGISTRATION_REQUEST_DATA, encodedBytes);
  }

  @Test
  public void testDecodeRegisterRequest() throws Exception {
    RegisterRequest registerRequest =
        RawMessageCodec.decodeRegisterRequest(REGISTRATION_REQUEST_DATA);

    assertEquals(new RegisterRequest(APP_ID_ENROLL_SHA256, BROWSER_DATA_ENROLL_SHA256),
        registerRequest);
  }

  @Test
  public void testEncodeRegisterResponse() throws Exception {
    RegisterResponse registerResponse = new RegisterResponse(USER_PUBLIC_KEY_ENROLL_HEX,
        KEY_HANDLE, VENDOR_CERTIFICATE, SIGNATURE_ENROLL);

    byte[] encodedBytes = RawMessageCodec.encodeRegisterResponse(registerResponse);

    assertArrayEquals(REGISTRATION_RESPONSE_DATA, encodedBytes);
  }

  @Test
  public void testEncodeRegisterSignedBytes() throws Exception {
    byte[] encodedBytes = RawMessageCodec.encodeRegistrationSignedBytes(APP_ID_ENROLL_SHA256,
        BROWSER_DATA_ENROLL_SHA256, KEY_HANDLE, USER_PUBLIC_KEY_ENROLL_HEX);

    assertArrayEquals(EXPECTED_REGISTER_SIGNED_BYTES, encodedBytes);
  }

  @Test
  public void testDecodeRegisterResponse() throws Exception {
    RegisterResponse registerResponse =
        RawMessageCodec.decodeRegisterResponse(REGISTRATION_RESPONSE_DATA);

    assertEquals(new RegisterResponse(USER_PUBLIC_KEY_ENROLL_HEX,
        KEY_HANDLE, VENDOR_CERTIFICATE, SIGNATURE_ENROLL), registerResponse);
  }

  @Test
  public void testEncodeAuthenticateRequest() throws Exception {
    AuthenticateRequest authenticateRequest = new AuthenticateRequest(
        AuthenticateRequest.USER_PRESENCE_SIGN, BROWSER_DATA_SIGN_SHA256, APP_ID_SIGN_SHA256,
        KEY_HANDLE);

    byte[] encodedBytes = RawMessageCodec.encodeAuthenticateRequest(authenticateRequest);

    assertArrayEquals(SIGN_REQUEST_DATA, encodedBytes);
  }

  @Test
  public void testDecodeAuthenticateRequest() throws Exception {
    AuthenticateRequest authenticateRequest =
        RawMessageCodec.decodeAuthenticateRequest(SIGN_REQUEST_DATA);

    assertEquals(new AuthenticateRequest(AuthenticateRequest.USER_PRESENCE_SIGN,
        BROWSER_DATA_SIGN_SHA256, APP_ID_SIGN_SHA256, KEY_HANDLE), authenticateRequest);
  }

  @Test
  public void testEncodeAuthenticateResponse() throws Exception {
    AuthenticateResponse authenticateResponse = new AuthenticateResponse(
        UserPresenceVerifier.USER_PRESENT_FLAG, COUNTER_VALUE, SIGNATURE_AUTHENTICATE);

    byte[] encodedBytes = RawMessageCodec.encodeAuthenticateResponse(authenticateResponse);

    assertArrayEquals(SIGN_RESPONSE_DATA, encodedBytes);
  }

  @Test
  public void testDecodeAuthenticateResponse() throws Exception {
    AuthenticateResponse authenticateResponse =
        RawMessageCodec.decodeAuthenticateResponse(SIGN_RESPONSE_DATA);

    assertEquals(new AuthenticateResponse(UserPresenceVerifier.USER_PRESENT_FLAG, COUNTER_VALUE,
        SIGNATURE_AUTHENTICATE), authenticateResponse);
  }

  @Test
  public void testEncodeAuthenticateSignedBytes() throws Exception {
    byte[] encodedBytes = RawMessageCodec.encodeAuthenticateSignedBytes(APP_ID_SIGN_SHA256,
        UserPresenceVerifier.USER_PRESENT_FLAG, COUNTER_VALUE, BROWSER_DATA_SIGN_SHA256);

    assertArrayEquals(EXPECTED_AUTHENTICATE_SIGNED_BYTES, encodedBytes);
  }
  
  @Test
  public void testDecodeTransferAccessResponse_equals() throws Exception {
    TransferAccessResponse transferAccessResponse =
        RawMessageCodec.decodeTransferAccessResponse(TRANSFER_ACCESS_RESPONSE_A_TO_B);
    byte controlByte = 0x03;
    TransferAccessMessage[] transferAccessMessages =
        {TransferAccessMessage.fromBytes(TRANSFER_ACCESS_MESSAGE_A_TO_B)};    
        
    assertEquals(new TransferAccessResponse(controlByte, transferAccessMessages, KEY_HANDLE_B,
        INITIAL_COUNTER, TRANSFER_ACCESS_RESPONSE_SIGNATURE_A_TO_B), transferAccessResponse);
  }
  
  @Test
  public void testDecodTransferAccessResponse_equals2() throws Exception {
    TransferAccessResponse transferAccessResponse = RawMessageCodec
        .decodeTransferAccessResponse(TRANSFER_ACCESS_RESPONSE_A_TO_B_TO_C_TO_D_NO_USER_PRESENCE);
    byte controlByte = 0x02;
    int counterValue = 2035434928;
    TransferAccessMessage[] transferAccessMessages = {
        TransferAccessMessage.fromBytes(TRANSFER_ACCESS_MESSAGE_A_TO_B), 
        TransferAccessMessage.fromBytes(TRANSFER_ACCESS_MESSAGE_B_TO_C),
        TransferAccessMessage.fromBytes(TRANSFER_ACCESS_MESSAGE_C_TO_D)};
    
    TransferAccessResponse referenceResponse =
        new TransferAccessResponse(controlByte, transferAccessMessages, KEY_HANDLE_D, counterValue,
            TRANSFER_ACCESS_RESPONSE_SIGNATURE_A_TO_B_TO_C_TO_D);
    
    assertEquals(referenceResponse, transferAccessResponse);
  }
  
  @Test
  public void testDecodeTransferAccessResponse_extraBytes() throws Exception {
    TransferAccessResponse transferAccessResponse =
        RawMessageCodec.decodeTransferAccessResponse(TRANSFER_ACCESS_RESPONSE_A_TO_B_EXTRA_BYTES);
    
    int numTransferAccessMessages = transferAccessResponse.getTransferAccessMessages().length;
    
    assertEquals(transferAccessResponse.getTransferAccessMessages()[numTransferAccessMessages - 1]
        .getNewAttestationCertificate(), VENDOR_CERTIFICATE);
    assertTrue(crypto.verifySignature(VENDOR_CERTIFICATE,
        EXPECTED_TRANSFER_ACCESS_RESPONSE_SIGNED_BYTES_A_TO_B,
        TRANSFER_ACCESS_RESPONSE_SIGNATURE_A_TO_B));
    
    assertNotEquals(transferAccessResponse.getSignature(),
        TRANSFER_ACCESS_RESPONSE_SIGNATURE_A_TO_B);
    assertTrue(
        crypto.verifySignature(
            VENDOR_CERTIFICATE,
            EXPECTED_TRANSFER_ACCESS_RESPONSE_SIGNED_BYTES_A_TO_B,
            transferAccessResponse.getSignature()));
  }
  
  @Test
  public void testDecodeTransferAccessResponse_invalidSignature() throws Exception {
    TransferAccessResponse transferAccessResponse = RawMessageCodec
        .decodeTransferAccessResponse(TRANSFER_ACCESS_RESPONSE_A_TO_B_INVALID_SIGNATURE);
    
    int numTransferAccessMessages = transferAccessResponse.getTransferAccessMessages().length;
    
    assertEquals(transferAccessResponse.getTransferAccessMessages()[numTransferAccessMessages - 1]
        .getNewAttestationCertificate(), VENDOR_CERTIFICATE);
    assertTrue(crypto.verifySignature(VENDOR_CERTIFICATE,
        EXPECTED_TRANSFER_ACCESS_RESPONSE_SIGNED_BYTES_A_TO_B,
        TRANSFER_ACCESS_RESPONSE_SIGNATURE_A_TO_B));
    
    assertNotEquals(transferAccessResponse.getSignature(),
        TRANSFER_ACCESS_RESPONSE_SIGNATURE_A_TO_B);
    assertFalse(
        crypto.verifySignature(
            VENDOR_CERTIFICATE,
            EXPECTED_TRANSFER_ACCESS_RESPONSE_SIGNED_BYTES_A_TO_B,
            transferAccessResponse.getSignature()));
  }

  @Test
  public void testDecodeTransferAccessResponse_tooFewBytes() throws Exception {
    try {
      RawMessageCodec.decodeTransferAccessResponse(TRANSFER_ACCESS_RESPONSE_A_TO_B_TOO_FEW_BYTES);
      fail("expected exception, but didn't get it");
    } catch (U2FException e) {
      assertTrue(e.getCause() instanceof java.io.EOFException);
    }
  }

  @Test
  public void testDecodeTransferAccessResponse_sequenceNumbersOutOfOrder() throws Exception {
    try {
      RawMessageCodec.decodeTransferAccessResponse(
          TRANSFER_ACCESS_RESPONSE_TRANSFER_ACCESS_MESSAGES_1_AND_2_OUT_OF_ORDER);
      fail("expected exception, but didn't get it");
    } catch (U2FException e) {
      assertTrue(e.getMessage()
          .contains("Messages not in order, unexptected sequence number. Expected 2, but got 1."));
    }
  }

  @Test
  public void testEncodeTransferAccessMessageSignedBytesForAuthenticationKey() throws Exception {
    byte sequenceNumber = 1;
    byte[] encodedBytes =
        RawMessageCodec.encodeTransferAccessMessageSignedBytesForAuthenticationKey(
            sequenceNumber,
            TRANSFER_ACCESS_PUBLIC_KEY_B_HEX,
            APP_ID_SIGN_SHA256,
            VENDOR_CERTIFICATE
            );

    assertArrayEquals(EXPECTED_TRANSFER_ACCESS_SIGNED_BYTES_FOR_AUTHENTICATION_KEY_A_TO_B,
        encodedBytes);
  }

  @Test
  public void encodeTransferAccessMessageSignedBytesForAttestationKey() throws Exception {
    byte sequenceNumber = 1;
    byte[] encodedBytes =
        RawMessageCodec.encodeTransferAccessMessageSignedBytesForAttestationKey(
            sequenceNumber,
            TRANSFER_ACCESS_PUBLIC_KEY_B_HEX,
            APP_ID_SIGN_SHA256,
            VENDOR_CERTIFICATE,
            TRANSFER_ACCESS_MESSAGE_SIGNATURE_USING_AUTHENTICATION_KEY_A_TO_B
            );

    assertArrayEquals(EXPECTED_TRANSFER_ACCESS_SIGNED_BYTES_FOR_ATTESTATION_KEY_A_TO_B,
        encodedBytes);
  }

  @Test
  public void encodeTransferAccessResponseSignedBytes() throws Exception {
    byte controlByte = 0x02;
    int counter = 2035434928;
    byte[] encodedBytes =
        RawMessageCodec.encodeTransferAccessResponseSignedBytes(
            controlByte,
            counter,
            BROWSER_DATA_SIGN_SHA256,
            KEY_HANDLE_D,
            computeSha256(TRANSFER_ACCESS_MESSAGE_C_TO_D)
            );

    assertArrayEquals(EXPECTED_TRANSFER_ACCESS_RESPONSE_SIGNED_BYTES_A_TO_B_TO_C_TO_D,
        encodedBytes);
  }
}
