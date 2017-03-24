// Copyright 2014 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package com.google.u2f;

import static com.google.u2f.TestUtils.computeSha256;
import static com.google.u2f.TestUtils.parseCertificate;
import static com.google.u2f.TestUtils.parseCertificateBase64;
import static com.google.u2f.TestUtils.parseCertificateChainBase64;
import static com.google.u2f.TestUtils.parseHex;
import static com.google.u2f.TestUtils.parsePrivateKey;
import static com.google.u2f.TestUtils.parsePublicKey;

import com.google.common.collect.ImmutableSet;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.apache.commons.codec.binary.Base64;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Set;

public class TestVectors {
  // Test vectors from FIDO U2F: Raw Message Formats - Draft 4
  protected static final int COUNTER_VALUE = 1;
  protected static final String ACCOUNT_NAME = "test@example.com";
  protected static final Set<String> TRUSTED_DOMAINS = ImmutableSet.of("http://example.com");
  protected static final String SESSION_ID = "session_id";
  protected static final String SESSION_ID_2 = "session_id_2";
  protected static final String APP_ID_ENROLL = "http://example.com";
  protected static final byte[] APP_ID_ENROLL_SHA256 = computeSha256(APP_ID_ENROLL);
  protected static final String APP_ID_SIGN = "https://gstatic.com/securitykey/a/example.com";
  protected static final byte[] APP_ID_SIGN_SHA256 = computeSha256(APP_ID_SIGN);
  protected static final String ORIGIN = "http://example.com";
  protected static final String SERVER_CHALLENGE_ENROLL_BASE64 =
      "vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo";
  protected static final byte[] SERVER_CHALLENGE_ENROLL =
      Base64.decodeBase64(SERVER_CHALLENGE_ENROLL_BASE64);
  protected static final String SERVER_CHALLENGE_SIGN_BASE64 =
      "opsXqUifDriAAmWclinfbS0e-USY0CgyJHe_Otd7z8o";
  protected static final byte[] SERVER_CHALLENGE_SIGN =
      Base64.decodeBase64(SERVER_CHALLENGE_SIGN_BASE64);
  protected static final String VENDOR_CERTIFICATE_HEX =
      "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce"
      + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
      + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
      + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
      + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
      + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
      + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
      + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
      + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
      + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df";
  protected static final X509Certificate VENDOR_CERTIFICATE =
      parseCertificate(VENDOR_CERTIFICATE_HEX);
  protected static final PrivateKey VENDOR_CERTIFICATE_PRIVATE_KEY =
      parsePrivateKey("f3fccc0d00d8031954f90864d43c247f4bf5f0665c6b50cc17749a27d1cf7664");
  protected static final String CHANNEL_ID_STRING =
      "{"
      + "\"kty\":\"EC\","
      + "\"crv\":\"P-256\","
      + "\"x\":\"HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8\","
      + "\"y\":\"XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4\""
      + "}";
  protected static final JsonObject CHANNEL_ID_JSON =
      (JsonObject) new JsonParser().parse(CHANNEL_ID_STRING);
  protected static final String BROWSER_DATA_ENROLL = String.format(
      "{"
      + "\"typ\":\"navigator.id.finishEnrollment\","
      + "\"challenge\":\"%s\","
      + "\"cid_pubkey\":%s,"
      + "\"origin\":\"%s\"}",
      SERVER_CHALLENGE_ENROLL_BASE64, CHANNEL_ID_STRING, ORIGIN);
  protected static final String BROWSER_DATA_ENROLL_BASE64 =
      Base64.encodeBase64URLSafeString(BROWSER_DATA_ENROLL.getBytes());
  protected static final byte[] BROWSER_DATA_ENROLL_SHA256 =
      computeSha256(BROWSER_DATA_ENROLL.getBytes());
  protected static final String BROWSER_DATA_SIGN = String.format(
      "{"
      + "\"typ\":\"navigator.id.getAssertion\","
      + "\"challenge\":\"%s\","
      + "\"cid_pubkey\":%s,"
      + "\"origin\":\"%s\"}",
      SERVER_CHALLENGE_SIGN_BASE64, CHANNEL_ID_STRING, ORIGIN);
  protected static final String BROWSER_DATA_SIGN_BASE64 =
      Base64.encodeBase64URLSafeString(BROWSER_DATA_SIGN.getBytes());
  protected static final byte[] BROWSER_DATA_SIGN_SHA256 =
      parseHex("ccd6ee2e47baef244d49a222db496bad0ef5b6f93aa7cc4d30c4821b3b9dbc57");
  protected static final String BROWSER_DATA_TRANSFER_ACCESS = String.format(
      "{"
      + "\"typ\":\"navigator.id.transferAccess\","
      + "\"challenge\":\"%s\","
      + "\"cid_pubkey\":%s,"
      + "\"origin\":\"%s\"}",
      SERVER_CHALLENGE_SIGN_BASE64, CHANNEL_ID_STRING, ORIGIN);
  protected static final String BROWSER_DATA_TRANSFER_ACCESS_BASE64 =
      Base64.encodeBase64URLSafeString(BROWSER_DATA_TRANSFER_ACCESS.getBytes());
  protected static final byte[] BROWSER_DATA_TRANSFER_ACCESS_SHA256 =
      parseHex("d35aaf508c3efab4afbf1c788e91762285337443a1fcb4b52d283bdd0b1649d6");
  
  protected static final byte[] REGISTRATION_REQUEST_DATA =
      parseHex("4142d21c00d94ffb9d504ada8f99b721f4b191ae4e37ca0140f696b6983cfacb"
          + "f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1c4");
  protected static final byte[] REGISTRATION_RESPONSE_DATA =
      parseHex("0504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b"
          + "657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2"
          + "f6d9402a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2"
          + "e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772"
          + "d70c253082013c3081e4a003020102020a47901280001155957352300a06082a"
          + "8648ce3d0403023017311530130603550403130c476e756262792050696c6f74"
          + "301e170d3132303831343138323933325a170d3133303831343138323933325a"
          + "3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34"
          + "373930313238303030313135353935373335323059301306072a8648ce3d0201"
          + "06082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c"
          + "1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23"
          + "abaf0203b4b8911ba0569994e101300a06082a8648ce3d040302034700304402"
          + "2060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30d"
          + "fa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b3"
          + "0410df304502201471899bcc3987e62e8202c9b39c33c19033f7340352dba80f"
          + "cab017db9230e402210082677d673d891933ade6f617e5dbde2e247e70423fd5"
          + "ad7804a6d3d3961ef871");
  protected static final String REGISTRATION_DATA_BASE64 =
      Base64.encodeBase64URLSafeString(REGISTRATION_RESPONSE_DATA);

  // Has Bluetooth Radio transport
  protected static final byte[] REGISTRATION_RESPONSE_DATA_ONE_TRANSPORT =
      parseHex("0504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc"
          + "6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9402a552d"
          + "fdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab6"
          + "1d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c253082019a30820140"
          + "a0030201020209012242000255962657300a06082a8648ce3d0403023045310b30090"
          + "603550406130241553113301106035504080c0a536f6d652d53746174653121301f06"
          + "0355040a0c18496e7465726e6574205769646769747320507479204c74643020170d3"
          + "135303830353136353131325a180f32303633303630373136353131325a3045310b30"
          + "090603550406130241553113301106035504080c0a536f6d652d53746174653121301"
          + "f060355040a0c18496e7465726e6574205769646769747320507479204c7464305930"
          + "1306072a8648ce3d020106082a8648ce3d030107034200042e09745f6e0f412a7a84b"
          + "367eb0b8dcb4a61d1fa336bbecfe30bd0a2c8faf74734a82fc03412589f4cc107f932"
          + "d3167e961eb664c3080347e505626c1d5d15cfa31730153013060b2b0601040182e51"
          + "c020101040403020780300a06082a8648ce3d040302034800304502202106e368bbe2"
          + "fc9f86991826b90a51c694b90fb7c01945e7a9531e4b65315ac5022100aa8e75a071e"
          + "645000376150c7faef1b8a57cb4bd41729c28d9b9bec744ebb4493045022070c1b332"
          + "667853491a525850b15599cc88be0433fc673be89e991b550921c2110221008326311"
          + "e0feaf1698110bed2c0737f3614298a8f265121f896db3cad459607fb");
  protected static final String REGISTRATION_RESPONSE_DATA_ONE_TRANSPORT_BASE64 =
      Base64.encodeBase64URLSafeString(REGISTRATION_RESPONSE_DATA_ONE_TRANSPORT);

  // Has Bluetooth Radio, Bluetooth Low Energy, and NFC transports
  protected static final byte[] REGISTRATION_RESPONSE_DATA_MULTIPLE_TRANSPORTS =
      parseHex("0504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc6"
          + "b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9402a552dfd"
          + "b7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab61d1"
          + "6591659cbaf00b4950f7abfe6660e2e006f76868b772d70c253082019930820140a003"
          + "0201020209012242000255962657300a06082a8648ce3d0403023045310b3009060355"
          + "0406130241553113301106035504080c0a536f6d652d53746174653121301f06035504"
          + "0a0c18496e7465726e6574205769646769747320507479204c74643020170d31353038"
          + "30353136343932345a180f32303633303630373136343932345a3045310b3009060355"
          + "0406130241553113301106035504080c0a536f6d652d53746174653121301f06035504"
          + "0a0c18496e7465726e6574205769646769747320507479204c74643059301306072a86"
          + "48ce3d020106082a8648ce3d030107034200042e09745f6e0f412a7a84b367eb0b8dcb"
          + "4a61d1fa336bbecfe30bd0a2c8faf74734a82fc03412589f4cc107f932d3167e961eb6"
          + "64c3080347e505626c1d5d15cfa31730153013060b2b0601040182e51c020101040403"
          + "0204d0300a06082a8648ce3d0403020347003044022058b52f205dc9772e1bef915973"
          + "6098290ffb5850769efd1c37cfc97141279e5f02200c4d91c96c457d1a607a0d16b0b5"
          + "47bbb2e5e2865490112e4b94607b3adcad18304402202548b5204488995f00c905d2b9"
          + "25ca2f9b8c0aba76faf3461dc6778864eb5ee3022005f2d852969864577e01c71cbb10"
          + "93412ef0fef518141d698cda2a45fe2bc767");
  protected static final String REGISTRATION_RESPONSE_DATA_MULTIPLE_TRANSPORTS_BASE64 =
      Base64.encodeBase64URLSafeString(REGISTRATION_RESPONSE_DATA_MULTIPLE_TRANSPORTS);

  protected static final byte[] REGISTRATION_RESPONSE_DATA_MALFORMED_TRANSPORTS =
      parseHex("0504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc6b"
          + "952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9402a552dfdb7"
          + "477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab61d1659"
          + "1659cbaf00b4950f7abfe6660e2e006f76868b772d70c25308201983082013ea0030201"
          + "020209012242000255962657300a06082a8648ce3d0403023045310b300906035504061"
          + "30241553113301106035504080c0a536f6d652d53746174653121301f060355040a0c18"
          + "496e7465726e6574205769646769747320507479204c74643020170d313530383036323"
          + "3333532385a180f32303633303630383233333532385a3045310b300906035504061302"
          + "41553113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496"
          + "e7465726e6574205769646769747320507479204c74643059301306072a8648ce3d0201"
          + "06082a8648ce3d030107034200042e09745f6e0f412a7a84b367eb0b8dcb4a61d1fa336"
          + "bbecfe30bd0a2c8faf74734a82fc03412589f4cc107f932d3167e961eb664c3080347e5"
          + "05626c1d5d15cfa31530133011060b2b0601040182e51c0201010402aa80300a06082a8"
          + "648ce3d0403020348003045022100907f965f33d857982b39d9f4c22ccb4a63359fc10a"
          + "af08a81997c0e04b73dc9b02204f45d556ae2ea71a5fdfa646b516584dada84954a5d8b"
          + "9d27bdb041e89b216b6304402206b5085168e0c0e850677d3423c0f3972860bd3fbf6d2"
          + "d98cd7af9e1d3f46269402201bde430c86260666bcaa23155296bd0627a8e48d98c2009"
          + "212bec8a7a77f7974");
  protected static final String REGISTRATION_RESPONSE_DATA_MALFORMED_TRANSPORTS_BASE64 =
      Base64.encodeBase64URLSafeString(REGISTRATION_RESPONSE_DATA_MALFORMED_TRANSPORTS);

  protected static final byte[] KEY_HANDLE =
      parseHex("2a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a"
          + "6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c25");
  protected static final String KEY_HANDLE_BASE64 = Base64.encodeBase64URLSafeString(KEY_HANDLE);
  protected static final byte[] USER_PUBLIC_KEY_ENROLL_HEX =
      parseHex("04b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b65"
          + "7c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6"
          + "d9");
  protected static final String USER_PRIVATE_KEY_ENROLL_HEX =
      "9a9684b127c5e3a706d618c86401c7cf6fd827fd0bc18d24b0eb842e36d16df1";
  protected static final PublicKey USER_PUBLIC_KEY_ENROLL =
      parsePublicKey(USER_PUBLIC_KEY_ENROLL_HEX);
  protected static final PrivateKey USER_PRIVATE_KEY_ENROLL =
      parsePrivateKey(USER_PRIVATE_KEY_ENROLL_HEX);
  protected static final KeyPair USER_KEY_PAIR_ENROLL =
      new KeyPair(USER_PUBLIC_KEY_ENROLL, USER_PRIVATE_KEY_ENROLL);
  protected static final String USER_PRIVATE_KEY_SIGN_HEX =
      "ffa1e110dde5a2f8d93c4df71e2d4337b7bf5ddb60c75dc2b6b81433b54dd3c0";
  protected static final byte[] USER_PUBLIC_KEY_SIGN_HEX =
      parseHex("04d368f1b665bade3c33a20f1e429c7750d5033660c019119d29aa4ba7abc04a"
          + "a7c80a46bbe11ca8cb5674d74f31f8a903f6bad105fb6ab74aefef4db8b0025e"
          + "1d");
  protected static final PublicKey USER_PUBLIC_KEY_SIGN = parsePublicKey(USER_PUBLIC_KEY_SIGN_HEX);
  protected static final PrivateKey USER_PRIVATE_KEY_SIGN =
      parsePrivateKey(USER_PRIVATE_KEY_SIGN_HEX);
  protected static final KeyPair USER_KEY_PAIR_SIGN =
      new KeyPair(USER_PUBLIC_KEY_SIGN, USER_PRIVATE_KEY_SIGN);
  protected static final byte[] SIGN_REQUEST_DATA =
      parseHex("03ccd6ee2e47baef244d49a222db496bad0ef5b6f93aa7cc4d30c4821b3b9dbc"
          + "574b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992"
          + "ca402a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3"
          + "925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d7"
          + "0c25");
  protected static final byte[] SIGN_RESPONSE_DATA =
      parseHex("0100000001304402204b5f0cd17534cedd8c34ee09570ef542a353df4436030c"
          + "e43d406de870b847780220267bb998fac9b7266eb60e7cb0b5eabdfd5ba9614f"
          + "53c7b22272ec10047a923f");
  protected static final String SIGN_RESPONSE_DATA_BASE64 =
      Base64.encodeBase64URLSafeString(SIGN_RESPONSE_DATA);
  // Transfer Access Message Vectors:
  protected static final String TRANSFER_ACCESS_PRIVATE_KEY_A_HEX = USER_PRIVATE_KEY_SIGN_HEX;
  protected static final byte[] TRANSFER_ACCESS_PUBLIC_KEY_A_HEX =  USER_PUBLIC_KEY_SIGN_HEX;
  protected static final String TRANSFER_ACCESS_PRIVATE_KEY_B_HEX = 
      "735592bcc125b8cecaffe046c42140c483198ae183b0554de104721a23c55d0e";
  protected static final byte[] TRANSFER_ACCESS_PUBLIC_KEY_B_HEX = 
      parseHex("04269889309e47b66749b855dbc03de26b84ea25b62349c1e09d986bea1f5cd0"
          + "f2f3be6b0f2bf7f54eae97764b378bc2313309b2ace492e2b410d97f2e8979c46d");
  protected static final String TRANSFER_ACCESS_PRIVATE_KEY_C_HEX = 
      "9498e92999270fcb3f4e28e59889ef88991f71c242637f52db003c46cdbc0da4";
  protected static final byte[] TRANSFER_ACCESS_PUBLIC_KEY_C_HEX = 
      parseHex("0416668f839b4ba154f70f452d8da81bc3fa93979a03cca5e6bec36b64473024"
          + "0317f932e2833bb4f780a0e81bc13ec392cba3f809794528e923f4af589b7761e4");
  protected static final String TRANSFER_ACCESS_PRIVATE_KEY_D_HEX = 
      "4c99183e73c39b95308d595cb3c007fffe61549231411881c8377f4e451ecee0";
  protected static final byte[] TRANSFER_ACCESS_PUBLIC_KEY_D_HEX = 
      parseHex("0472dc3ca63129c6354890309a89f10b51a8f7c49fc2a7ed554f8886fb7fe7ea"
          + "2f0e8a51345478d7a726b55aad8177bbc826d55395442fbb986d2b323c48f918c8");
  protected static final byte[] KEY_HANDLE_A = KEY_HANDLE;
  protected static final String KEY_HANDLE_A_BASE64 =
      Base64.encodeBase64URLSafeString(KEY_HANDLE_A);
  protected static final byte[] KEY_HANDLE_B = 
      parseHex("746ee0dcb3891b4fffe151a035c2e878f1dc0dea6c51455b5b32bcfa046974d8"
          + "f820cc9ca846cfd3b4f429d205d71904475fc143da8cfb61eeeeba69b5bf1d7a");
  protected static final String KEY_HANDLE_B_BASE64 =
      Base64.encodeBase64URLSafeString(KEY_HANDLE_B);
  protected static final byte[] KEY_HANDLE_C = 
      parseHex("b6f027b7d3f1d3c33510b16f9e3931bf2e1032622be5f1fa959d1b1af7d5fb96"
          + "a6cea13c201edf823a929df8b170d17c473770b605c9245b421a028e90b3d684");
  protected static final String KEY_HANDLE_C_BASE64 =
      Base64.encodeBase64URLSafeString(KEY_HANDLE_C);
  protected static final byte[] KEY_HANDLE_D = 
      parseHex("9b31362dc861c620da55569e7e493d9858d2cb8ec5fc33b75bf809610aee5523"
          + "5a7f496a803099a3c4f7e288cfa74a2b7f0fffcf70bb4396b7abf4841c46303d");
  protected static final String KEY_HANDLE_D_BASE64 =
      Base64.encodeBase64URLSafeString(KEY_HANDLE_D);

  protected static final byte[] TRANSFER_ACCESS_MESSAGE_A_TO_B = 
      parseHex("01"                                                            // Sequence Number
          + "04269889309e47b66749b855dbc03de26b84ea25b62349c1e09d986bea1f5cd0" // Phone B Public Key
          + "f2f3be6b0f2bf7f54eae97764b378bc2313309b2ace492e2b410d97f2e8979c46d"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca" // AplicationSha256
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce" // Attestation Cert
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
          + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df" 
          + "47"                               // Length of signature with Authentication Key in Hex
          + "30450221008739a7dd67973a270a34081261c9d30048163174fca0e80c14ff72" // Signature Using
          + "e449128303022010d1b8edf71fc53814b363582c93fb66306baee74a06eb4f9b" // Authentication Key
          + "1f06d7956aebca"
          + "47"                               // Length of signature with Attestation Key in Hex
          + "3045022038aa3cedbb2c5b59349031071130894fee62a2dbd9553c063ced4b77" // Signature Using
          + "868c0a23022100bb60d474eb4e0e4bcf65d20142ab3c8ce7438779e2b2878ef8" // Attestation Key
          + "8bb0acb607172e"
          );
  protected static final byte[] TRANSFER_ACCESS_RESPONSE_A_TO_B = 
      parseHex("03" // Control Byte
          + "01"                                                          // TRANSFER_ACCESS_MESSAGE
          + "04269889309e47b66749b855dbc03de26b84ea25b62349c1e09d986bea1f5cd0" 
          + "f2f3be6b0f2bf7f54eae97764b378bc2313309b2ace492e2b410d97f2e8979c46d"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca" 
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce"
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
          + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df" 
          + "47"                                    
          + "30450221008739a7dd67973a270a34081261c9d30048163174fca0e80c14ff72"
          + "e449128303022010d1b8edf71fc53814b363582c93fb66306baee74a06eb4f9b"
          + "1f06d7956aebca"
          + "47"                               
          + "3045022038aa3cedbb2c5b59349031071130894fee62a2dbd9553c063ced4b77" 
          + "868c0a23022100bb60d474eb4e0e4bcf65d20142ab3c8ce7438779e2b2878ef8"
          + "8bb0acb607172e"                                          // END TRANSFER_ACCESS_MESSAGE
          + "40"                                                               // Key Handle Length
          + "746ee0dcb3891b4fffe151a035c2e878f1dc0dea6c51455b5b32bcfa046974d8" // New Key Handle (B)
          + "f820cc9ca846cfd3b4f429d205d71904475fc143da8cfb61eeeeba69b5bf1d7a"
          + "00000000" // Counter Initial Value
          + "3046022100fe66adfae4e95773d4deee14fda48cdd12a3343d65c1237166a6e3" // Signature
          + "f164575f17022100b5a9e6d34e5644817cc5f3478bd5940d66b089e449db57c4"
          + "e2a14bbfcf593932"
          );
  protected static final String TRANSFER_ACCESS_RESPONSE_A_TO_B_BASE64 = 
      Base64.encodeBase64URLSafeString(TRANSFER_ACCESS_RESPONSE_A_TO_B); 
  protected static final byte[] TRANSFER_ACCESS_RESPONSE_A_TO_B_NO_USER_PRESENCE = 
      parseHex("02" // Control Byte
          + "01"                                                          // TRANSFER_ACCESS_MESSAGE
          + "04269889309e47b66749b855dbc03de26b84ea25b62349c1e09d986bea1f5cd0" 
          + "f2f3be6b0f2bf7f54eae97764b378bc2313309b2ace492e2b410d97f2e8979c46d"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca" 
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce"
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
          + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df" 
          + "47"                                    
          + "30450221008739a7dd67973a270a34081261c9d30048163174fca0e80c14ff72"
          + "e449128303022010d1b8edf71fc53814b363582c93fb66306baee74a06eb4f9b"
          + "1f06d7956aebca"
          + "47"                               
          + "3045022038aa3cedbb2c5b59349031071130894fee62a2dbd9553c063ced4b77" 
          + "868c0a23022100bb60d474eb4e0e4bcf65d20142ab3c8ce7438779e2b2878ef8"
          + "8bb0acb607172e"                                          // END TRANSFER_ACCESS_MESSAGE
          + "40"                                                               // Key Handle Length
          + "746ee0dcb3891b4fffe151a035c2e878f1dc0dea6c51455b5b32bcfa046974d8" // New Key Handle (B)
          + "f820cc9ca846cfd3b4f429d205d71904475fc143da8cfb61eeeeba69b5bf1d7a"
          + "00000000" // Counter Initial Value
          + "3046022100e1608951f34e345ed215d480a946c92611bfc7414db375464c2bd4" // Signature
          + "91a7fa171d022100e7ddc674731be7a85d9e67511259249cd0584599f1dc21a8"
          + "a233785effd92235"
          );
  protected static final String TRANSFER_ACCESS_RESPONSE_A_TO_B_NO_USER_PRESENCE_BASE64 = 
      Base64.encodeBase64URLSafeString(TRANSFER_ACCESS_RESPONSE_A_TO_B_NO_USER_PRESENCE); 
  protected static final byte[] TRANSFER_ACCESS_MESSAGE_B_TO_C = 
      parseHex("02"                                                            // Sequence Number
          + "0416668f839b4ba154f70f452d8da81bc3fa93979a03cca5e6bec36b64473024" // Phone C Public Key
          + "0317f932e2833bb4f780a0e81bc13ec392cba3f809794528e923f4af589b7761e4"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca" // AplicationSha256
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce" // Attestation Cert
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
          + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df" 
          + "46"                            // Length (in hex) of signature with Authentication Key
          + "30440220181662b45a4f61796243eefaf2383248f68d28d67d987bc3034261bd" // Signature with
          + "aa3351d9022064ab547e14c4c32c89073e4e0396e8501d9404952a6dda4f653b" // Authentication Key
          + "d99077e95acf"
          + "48"                            // Length (in hex) of signature with Attestation Key
          + "3046022100fb265cdca056fad77a3d5a0f293c15af0344447fbf1693ccf361e9" // Signature with
          + "5651cef73502210093e2e15e77796422c09c23bf9fb8c6af4acf3e597b9bd4d3" // Attestation Key
          + "c92e7e0781be9dbb"
          );
  protected static final byte[] TRANSFER_ACCESS_MESSAGE_C_TO_D = 
      parseHex("03"                                                            // SequenceNumber
          + "0472dc3ca63129c6354890309a89f10b51a8f7c49fc2a7ed554f8886fb7fe7ea" // Phone D Public Key
          + "2f0e8a51345478d7a726b55aad8177bbc826d55395442fbb986d2b323c48f918c8"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca" // AplicationSha256
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce" // Attestation Cert
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
          + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df" 
          + "47"                            // Length (in hex) of signature with Authentication Key
          + "30450221009c26611bd6ccc27d1925c64d9ee9f28483de46e36df47c7a709cf7" // Signature with
          + "b3490cde1902202620c2ddf59176f749a5f9566d5928e7dd1ca72166ca78ad6d" // Authentication Key
          + "90c0b1e330ca59"
          + "48"                            // Length (in hex) of signature with Attestation Key
          + "3046022100fa805fe66e7d415c0299c66d2ba8a211c4af102fad1628e66017b8" // Signature with
          + "6eabb97c36022100f37f49ad0084cc7b934abd9e1fc327d0964ba351ce4b6dca" // Attestation Key
          + "8e2a6e8c0aa4013b"
          );
  protected static final byte[] TRANSFER_ACCESS_RESPONSE_A_TO_B_TO_C_TO_D_NO_USER_PRESENCE = 
      parseHex("02"                                                             // Control Byte
          + "03"                                            // TRANSFER_ACCESS_MESSAGE chain, C to D
          + "0472dc3ca63129c6354890309a89f10b51a8f7c49fc2a7ed554f8886fb7fe7ea"
          + "2f0e8a51345478d7a726b55aad8177bbc826d55395442fbb986d2b323c48f918c8"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca"
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce"
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
          + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df" 
          + "47"
          + "30450221009c26611bd6ccc27d1925c64d9ee9f28483de46e36df47c7a709cf7"
          + "b3490cde1902202620c2ddf59176f749a5f9566d5928e7dd1ca72166ca78ad6d"
          + "90c0b1e330ca59"
          + "48"
          + "3046022100fa805fe66e7d415c0299c66d2ba8a211c4af102fad1628e66017b8"
          + "6eabb97c36022100f37f49ad0084cc7b934abd9e1fc327d0964ba351ce4b6dca"
          + "8e2a6e8c0aa4013b"
          + "02"                                            // TRANSFER_ACCESS_MESSAGE chain, B to C
          + "0416668f839b4ba154f70f452d8da81bc3fa93979a03cca5e6bec36b64473024"
          + "0317f932e2833bb4f780a0e81bc13ec392cba3f809794528e923f4af589b7761e4"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca"
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce"
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
          + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df" 
          + "46"
          + "30440220181662b45a4f61796243eefaf2383248f68d28d67d987bc3034261bd"
          + "aa3351d9022064ab547e14c4c32c89073e4e0396e8501d9404952a6dda4f653b"
          + "d99077e95acf"
          + "48"
          + "3046022100fb265cdca056fad77a3d5a0f293c15af0344447fbf1693ccf361e9"
          + "5651cef73502210093e2e15e77796422c09c23bf9fb8c6af4acf3e597b9bd4d3"
          + "c92e7e0781be9dbb"          
          + "01"                                            // TRANSFER_ACCESS_MESSAGE chain, A to B
          + "04269889309e47b66749b855dbc03de26b84ea25b62349c1e09d986bea1f5cd0" 
          + "f2f3be6b0f2bf7f54eae97764b378bc2313309b2ace492e2b410d97f2e8979c46d"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca" 
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce"
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
          + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df" 
          + "47"
          + "30450221008739a7dd67973a270a34081261c9d30048163174fca0e80c14ff72"
          + "e449128303022010d1b8edf71fc53814b363582c93fb66306baee74a06eb4f9b"
          + "1f06d7956aebca"
          + "47"
          + "3045022038aa3cedbb2c5b59349031071130894fee62a2dbd9553c063ced4b77"
          + "868c0a23022100bb60d474eb4e0e4bcf65d20142ab3c8ce7438779e2b2878ef8"
          + "8bb0acb607172e"                                // End TRANSFER_ACCESS_MESSAGE chain
          + "40"                                                               // Key Handle Length
          + "9b31362dc861c620da55569e7e493d9858d2cb8ec5fc33b75bf809610aee5523" // New Key Handle (D)
          + "5a7f496a803099a3c4f7e288cfa74a2b7f0fffcf70bb4396b7abf4841c46303d"
          + "795245b0" // Counter Initial Value
          + "3046022100947c47239a4fe51b406e1df077c3fbc3bf9add8d1202e2cf7d3ec1" // Signature
          + "bdfa41ced80221008ce7f4c529e7396e079456e56e70ec101a3d5bcb9b53e986"
          + "33abd0055c06180e"
          );
  protected static final String TRANSFER_ACCESS_RESPONSE_A_TO_B_TO_C_TO_D_NO_USER_PRESENCE_BASE64 = 
      Base64.encodeBase64URLSafeString(TRANSFER_ACCESS_RESPONSE_A_TO_B_TO_C_TO_D_NO_USER_PRESENCE);
  protected static final byte[] TRANSFER_ACCESS_MESSAGE_EXTRA_BYTES = 
      parseHex("01"                                                            // Sequence Number
          + "04269889309e47b66749b855dbc03de26b84ea25b62349c1e09d986bea1f5cd0" // Phone B Public Key
          + "f2f3be6b0f2bf7f54eae97764b378bc2313309b2ace492e2b410d97f2e8979c46d"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca" // AplicationSha256
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce" // Attestation Cert
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
          + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df" 
          + "47"                               // Length of signature with Authentication Key in Hex
          + "30450221008739a7dd67973a270a34081261c9d30048163174fca0e80c14ff72" // Signature Using
          + "e449128303022010d1b8edf71fc53814b363582c93fb66306baee74a06eb4f9b" // Authentication Key
          + "1f06d7956aebca"
          + "47"                               // Length of signature with Attestation Key in Hex
          + "3045022038aa3cedbb2c5b59349031071130894fee62a2dbd9553c063ced4b77" // Signature Using
          + "868c0a23022100bb60d474eb4e0e4bcf65d20142ab3c8ce7438779e2b2878ef8" // Attestation Key
          + "8bb0acb607172e"
          + "00"                                                               // Extra Bytes
          );
  protected static final byte[] TRANSFER_ACCESS_MESSAGE_TOO_FEW_BYTES = 
      parseHex("01"                                                            // Sequence Number
          + "04269889309e47b66749b855dbc03de26b84ea25b62349c1e09d986bea1f5cd0" // Phone B Public Key
          + "f2f3be6b0f2bf7f54eae97764b378bc2313309b2ace492e2b410d97f2e8979c46d"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca" // AplicationSha256
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce" // Attestation Cert
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
          + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df" 
          + "47"                               // Length of signature with Authentication Key in Hex
          + "30450221008739a7dd67973a270a34081261c9d30048163174fca0e80c14ff72" // Signature Using
          + "e449128303022010d1b8edf71fc53814b363582c93fb66306baee74a06eb4f9b" // Authentication Key
          + "1f06d7956aebca"
          + "47"                               // Length of signature with Attestation Key in Hex
          + "3045022038aa3cedbb2c5b59349031071130894fee62a2dbd9553c063ced4b77" // Shortened Signature
          + "868c0a23022100bb60d474eb4e0e4bcf65d20142ab3c8ce7438779e2b2878ef8" // with Attestation Key
          );
  protected static final byte[] TRANSFER_ACCESS_MESSAGE_WAY_TOO_FEW_BYTES = 
      parseHex("01"                                                            // Sequence Number
          + "04269889309e47b66749b855dbc03de26b84ea25b62349c1e09d986bea1f5cd0" // Phone B Public Key
          + "f2f3be6b0f2bf7f54eae97764b378bc2313309b2ace492e2b410d97f2e8979c4" 
          );
  protected static final byte[] TRANSFER_ACCESS_MESSAGE_BAD_AUTHENTICATION_SIGNATURE = 
      parseHex("01"                                                            // Sequence Number
          + "04269889309e47b66749b855dbc03de26b84ea25b62349c1e09d986bea1f5cd0" // Phone B Public Key
          + "f2f3be6b0f2bf7f54eae97764b378bc2313309b2ace492e2b410d97f2e8979c46d"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca" // AplicationSha256
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce" // Attestation Cert
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
          + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df" 
          + "47"                               // Length of signature with Authentication Key in Hex
          + "3045022074ad6fff533085578959d556f5737f5e4a79e4f6dfb7ed5c3e8a8d4e" // Signature with Authentication Key
          + "5825c1dc02210091fd5b8619f168453927a141de9728a599eeae080d0ea023e2"
          + "a6333a2671f737"
          + "47"                               // Length of signature with Attestation Key in Hex
          + "3045022038aa3cedbb2c5b59349031071130894fee62a2dbd9553c063ced4b77" // Signature Using
          + "868c0a23022100bb60d474eb4e0e4bcf65d20142ab3c8ce7438779e2b2878ef8" // Attestation Key
          + "8bb0acb607172e"
          );
  protected static final byte[] TRANSFER_ACCESS_MESSAGE_BAD_ATTESTATION_SIGNATURE = 
      parseHex("01"                                                            // Sequence Number
          + "04269889309e47b66749b855dbc03de26b84ea25b62349c1e09d986bea1f5cd0" // Phone B Public Key
          + "f2f3be6b0f2bf7f54eae97764b378bc2313309b2ace492e2b410d97f2e8979c46d"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca" // AplicationSha256
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce" // Attestation Cert
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
          + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df" 
          + "47"                               // Length of signature with Authentication Key in Hex
          + "30450221008739a7dd67973a270a34081261c9d30048163174fca0e80c14ff72" // Signature Using
          + "e449128303022010d1b8edf71fc53814b363582c93fb66306baee74a06eb4f9b" // Authentication Key
          + "1f06d7956aebca"
          + "48"                               // Length of signature with Attestation Key in Hex
          + "3046022100ac24d9bede458ba2ac81f08b342e858af377b2972cbbd509353fba" // Bad Signature with
          + "592f2cd255022100bfd41a37a4ff2ed622517e11ecac89bd4e9b335aa22fc409" // Attestation Key
          + "5c03b0a01f1d369e"
          );
  protected static final byte[] TRANSFER_ACCESS_MESSAGE_CUT_ATTESTATION_CERT = 
      parseHex("01"                                                            // Sequence Number
          + "04269889309e47b66749b855dbc03de26b84ea25b62349c1e09d986bea1f5cd0" // Phone B Public Key
          + "f2f3be6b0f2bf7f54eae97764b378bc2313309b2ace492e2b410d97f2e8979c46d"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca" // AplicationSha256
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce" // Attestation Cert
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "47"                               // Length of signature with Authentication Key in Hex
          + "30450221008739a7dd67973a270a34081261c9d30048163174fca0e80c14ff72" // Signature Using
          + "e449128303022010d1b8edf71fc53814b363582c93fb66306baee74a06eb4f9b" // Authentication Key
          + "1f06d7956aebca"
          + "47"                               // Length of signature with Attestation Key in Hex
          + "3045022038aa3cedbb2c5b59349031071130894fee62a2dbd9553c063ced4b77" // Signature Using
          + "868c0a23022100bb60d474eb4e0e4bcf65d20142ab3c8ce7438779e2b2878ef8" // Attestation Key
          + "8bb0acb607172e"
          );
  protected static final byte[] TRANSFER_ACCESS_MESSAGE_DOUBLE_CUT_ATTESTATION_CERT = 
      parseHex("01"                                                            // Sequence Number
          + "04269889309e47b66749b855dbc03de26b84ea25b62349c1e09d986bea1f5cd0" // Phone B Public Key
          + "f2f3be6b0f2bf7f54eae97764b378bc2313309b2ace492e2b410d97f2e8979c46d"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca" // AplicationSha256
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce" // Attestation Cert
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "47"                               // Length of signature with Authentication Key in Hex
          + "30450221008739a7dd67973a270a34081261c9d30048163174fca0e80c14ff72" // Signature Using
          + "e449128303022010d1b8edf71fc53814b363582c93fb66306baee74a06eb4f9b" // Authentication Key
          + "1f06d7956aebca"
          + "47"                               // Length of signature with Attestation Key in Hex
          + "3045022038aa3cedbb2c5b59349031071130894fee62a2dbd9553c063ced4b77" // Signature Using
          + "868c0a23022100bb60d474eb4e0e4bcf65d20142ab3c8ce7438779e2b2878ef8" // Attestation Key
          + "8bb0acb607172e"
          );
  protected static final byte[] TRANSFER_ACCESS_RESPONSE_A_TO_B_EXTRA_BYTES = 
      parseHex("03" // Control Byte
          + "01"                                                          // TRANSFER_ACCESS_MESSAGE          
          + "04269889309e47b66749b855dbc03de26b84ea25b62349c1e09d986bea1f5cd0" 
          + "f2f3be6b0f2bf7f54eae97764b378bc2313309b2ace492e2b410d97f2e8979c46d"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca" 
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce"
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
          + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df" 
          + "47"                                    
          + "30450221008739a7dd67973a270a34081261c9d30048163174fca0e80c14ff72"
          + "e449128303022010d1b8edf71fc53814b363582c93fb66306baee74a06eb4f9b"
          + "1f06d7956aebca"
          + "47"                               
          + "3045022038aa3cedbb2c5b59349031071130894fee62a2dbd9553c063ced4b77" 
          + "868c0a23022100bb60d474eb4e0e4bcf65d20142ab3c8ce7438779e2b2878ef8"
          + "8bb0acb607172e"                                          // END TRANSFER_ACCESS_MESSAGE
          + "40"                                                               // Key Handle Length
          + "746ee0dcb3891b4fffe151a035c2e878f1dc0dea6c51455b5b32bcfa046974d8" // New Key Handle (B)
          + "f820cc9ca846cfd3b4f429d205d71904475fc143da8cfb61eeeeba69b5bf1d7a"
          + "00000000" // Counter Initial Value
          + "3046022100fe66adfae4e95773d4deee14fda48cdd12a3343d65c1237166a6e3" // Signature
          + "f164575f17022100b5a9e6d34e5644817cc5f3478bd5940d66b089e449db57c4"
          + "e2a14bbfcf593932"
          + "deffaf"                                                               // Extra Bytes
          );
  protected static final byte[] TRANSFER_ACCESS_RESPONSE_A_TO_B_INVALID_SIGNATURE = 
      parseHex("03" // Control Byte
          + "01"                                                          // TRANSFER_ACCESS_MESSAGE
          + "04269889309e47b66749b855dbc03de26b84ea25b62349c1e09d986bea1f5cd0" 
          + "f2f3be6b0f2bf7f54eae97764b378bc2313309b2ace492e2b410d97f2e8979c46d"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca" 
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce"
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
          + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df" 
          + "47"                                    
          + "30450221008739a7dd67973a270a34081261c9d30048163174fca0e80c14ff72"
          + "e449128303022010d1b8edf71fc53814b363582c93fb66306baee74a06eb4f9b"
          + "1f06d7956aebca"
          + "47"                               
          + "3045022038aa3cedbb2c5b59349031071130894fee62a2dbd9553c063ced4b77" 
          + "868c0a23022100bb60d474eb4e0e4bcf65d20142ab3c8ce7438779e2b2878ef8"
          + "8bb0acb607172e"                                          // END TRANSFER_ACCESS_MESSAGE
          + "40"                                                               // Key Handle Length
          + "746ee0dcb3891b4fffe151a035c2e878f1dc0dea6c51455b5b32bcfa046974d8" // New Key Handle (B)
          + "f820cc9ca846cfd3b4f429d205d71904475fc143da8cfb61eeeeba69b5bf1d7a"
          + "00000000" // Counter Initial Value
          + "304402203a8ae240aea2ff9e5a2b72623a01cb78d514f82360ac897cf397131e" // Invalid Signature
          + "06de3450022044313f61bcca79a3353f89a34a53ddfd1fb6a6d288544c019d85"
          + "ee1e5ccb95ff"
          );
  protected static final byte[] TRANSFER_ACCESS_RESPONSE_A_TO_B_TOO_FEW_BYTES = 
      parseHex("03" // Control Byte
          + "01"                                                          // TRANSFER_ACCESS_MESSAGE
          + "04269889309e47b66749b855dbc03de26b84ea25b62349c1e09d986bea1f5cd0" 
          + "f2f3be6b0f2bf7f54eae97764b378bc2313309b2ace492e2b410d97f2e8979c46d"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca" 
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce"
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
          + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df" 
          + "47"                                    
          + "30450221008739a7dd67973a270a34081261c9d30048163174fca0e80c14ff72"
          + "e449128303022010d1b8edf71fc53814b363582c93fb66306baee74a06eb4f9b"
          + "1f06d7956aebca"
          + "47"                               
          + "3045022038aa3cedbb2c5b59349031071130894fee62a2dbd9553c063ced4b77" 
          + "868c0a23022100bb60d474eb4e0e4bcf65d20142ab3c8ce7438779e2b2878ef8"
          + "8bb0acb607172e"                                          // END TRANSFER_ACCESS_MESSAGE
          + "40"                                                               // Key Handle Length
          + "746ee0dcb3891b4fffe151a035c2e878f1dc0dea6c51455b5b32bcfa046974d8" // New Key Handle (B)
          + "f820cc9ca846cfd3b4f429d205d71904475fc143da8cfb61eeeeba69b5bf1d7a"
          + "000000"                                                           // Truncated Counter
          );
  protected static final byte[] TRANSFER_ACCESS_RESPONSE_TRANSFER_ACCESS_MESSAGES_1_AND_2_OUT_OF_ORDER = 
      parseHex("02"                                                             // Control Byte
          + "03"                                            // TRANSFER_ACCESS_MESSAGE chain, C to D
          + "0416668f839b4ba154f70f452d8da81bc3fa93979a03cca5e6bec36b64473024"
          + "0317f932e2833bb4f780a0e81bc13ec392cba3f809794528e923f4af589b7761e4"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca"
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce"
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
          + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df" 
          + "47"
          + "30450221009b5583388e34bd5efb8699bdb6ecaaf8864322ce7f27ec50b526c0"
          + "453e75cec202205f4f8371fa9a20b884295946c85995115dbbbd00f43f0e64ce"
          + "41745e039516d0"
          + "46"
          + "304402206108ca00030d57086ac3f41be47bae5a093f35d8e05403e1f3fa8160"
          + "c7acff77022019cacc489a5fffe89cc89523c35c6743d75bd28fc9b54f289404"
          + "65da527e3e49"
          + "01"                                            // TRANSFER_ACCESS_MESSAGE chain, A to B
          + "04269889309e47b66749b855dbc03de26b84ea25b62349c1e09d986bea1f5cd0" 
          + "f2f3be6b0f2bf7f54eae97764b378bc2313309b2ace492e2b410d97f2e8979c46d"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca" 
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce"
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
          + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df" 
          + "47"
          + "30450221008739a7dd67973a270a34081261c9d30048163174fca0e80c14ff72"
          + "e449128303022010d1b8edf71fc53814b363582c93fb66306baee74a06eb4f9b"
          + "1f06d7956aebca"
          + "47"
          + "3045022038aa3cedbb2c5b59349031071130894fee62a2dbd9553c063ced4b77"
          + "868c0a23022100bb60d474eb4e0e4bcf65d20142ab3c8ce7438779e2b2878ef8"
          + "8bb0acb607172e"           
          + "02"                                            // TRANSFER_ACCESS_MESSAGE chain, B to C
          + "0416668f839b4ba154f70f452d8da81bc3fa93979a03cca5e6bec36b64473024" 
          + "0317f932e2833bb4f780a0e81bc13ec392cba3f809794528e923f4af589b7761e4"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca" 
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce"
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
          + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df" 
          + "48"                       
          + "304602210092682c7525159aade790a87079913d7551773bf397da0c071726f9"
          + "82f047c86f022100a26eedbe8a6e6408d87a255f4451bab8982a936adde01c18"
          + "7bf293fd5fe57b8d"
          + "47"
          + "3045022100f2ebe8c3e201c3ba64a92567a25ed2c5f8b864b05b8730ef70c239"
          + "055df28ad402201736e5ab3bc6713b8afe8826e1e5395718a63a5a48cc1d3555"
          + "023d4c6650bc00"                                    // End TRANSFER_ACCESS_MESSAGE chain
          + "40"                                                               // Key Handle Length
          + "9b31362dc861c620da55569e7e493d9858d2cb8ec5fc33b75bf809610aee5523" // New Key Handle (D)
          + "5a7f496a803099a3c4f7e288cfa74a2b7f0fffcf70bb4396b7abf4841c46303d"
          + "795245b0" // Counter Initial Value
          + "3046022100f4eb7d82ecf05a5a6e78f194722fab165fe4970d1789a0c894ea5a" // Signature
          + "4217eacbf2022100f3880dffe75bb9366a0bfb7fe75ac803fee0ae8095ec5d97"
          + "48e48ad153b65b6f"
          );
  protected static final String TRANSFER_ACCESS_RESPONSE_TRANSFER_ACCESS_MESSAGES_1_AND_2_OUT_OF_ORDER_BASE64 =
      Base64.encodeBase64URLSafeString(
          TRANSFER_ACCESS_RESPONSE_TRANSFER_ACCESS_MESSAGES_1_AND_2_OUT_OF_ORDER);

  protected static final byte[] EXPECTED_REGISTER_SIGNED_BYTES =
      parseHex("00f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1"
          + "c44142d21c00d94ffb9d504ada8f99b721f4b191ae4e37ca0140f696b6983cfa"
          + "cb2a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e392"
          + "5a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c"
          + "2504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b"
          + "657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2"
          + "f6d9");
  protected static final byte[] EXPECTED_AUTHENTICATE_SIGNED_BYTES =
      parseHex("4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca"
          + "0100000001ccd6ee2e47baef244d49a222db496bad0ef5b6f93aa7cc4d30c482"
          + "1b3b9dbc57");
  protected static final byte[] SIGNATURE_ENROLL =
      parseHex("304502201471899bcc3987e62e8202c9b39c33c19033f7340352dba80fcab017"
          + "db9230e402210082677d673d891933ade6f617e5dbde2e247e70423fd5ad7804"
          + "a6d3d3961ef871");
  protected static final byte[] SIGNATURE_AUTHENTICATE =
      parseHex("304402204b5f0cd17534cedd8c34ee09570ef542a353df4436030ce43d406de8"
          + "70b847780220267bb998fac9b7266eb60e7cb0b5eabdfd5ba9614f53c7b22272"
          + "ec10047a923f");
  protected static final byte[] EXPECTED_TRANSFER_ACCESS_SIGNED_BYTES_FOR_AUTHENTICATION_KEY_A_TO_B =
      parseHex("01"                                                            // Sequence Number
          + "04269889309e47b66749b855dbc03de26b84ea25b62349c1e09d986bea1f5cd0" // New Public Key 
          + "f2f3be6b0f2bf7f54eae97764b378bc2313309b2ace492e2b410d97f2e8979c46d"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca" // ApplicationSha256
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce" // Attestation Cert
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
          + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df");
  protected static final byte[] EXPECTED_TRANSFER_ACCESS_SIGNED_BYTES_FOR_ATTESTATION_KEY_A_TO_B =
      parseHex("01"                                                            // Sequence Number
          + "04269889309e47b66749b855dbc03de26b84ea25b62349c1e09d986bea1f5cd0" // New Public Key 
          + "f2f3be6b0f2bf7f54eae97764b378bc2313309b2ace492e2b410d97f2e8979c46d"
          + "4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca" // ApplicationSha256
          + "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce" // Attestation Cert
          + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
          + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
          + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
          + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
          + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
          + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
          + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
          + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
          + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df" 
          + "30450221008739a7dd67973a270a34081261c9d30048163174fca0e80c14ff72" // Signature using
          + "e449128303022010d1b8edf71fc53814b363582c93fb66306baee74a06eb4f9b" // Authentication Key
          + "1f06d7956aebca");
  protected static final byte[] EXPECTED_TRANSFER_ACCESS_RESPONSE_SIGNED_BYTES_A_TO_B = 
      parseHex("03"                                                             // Control Byte
          + "00000000"                                                          // Counter
          + "a29b17a9489f0eb88002659c9629df6d2d1ef94498d028322477bf3ad77bcfca"  // SERVER_CHALLENGE_SIGN
          + "746ee0dcb3891b4fffe151a035c2e878f1dc0dea6c51455b5b32bcfa046974d8"  // New Key Handle(B)
          + "f820cc9ca846cfd3b4f429d205d71904475fc143da8cfb61eeeeba69b5bf1d7a"
          + "465ce92d2284820726e33bcdee5e52b6b3bd0b647197c9635413a11be4da7e75"  // Sha256 of TRANSFER_ACCESS_MESSAGE_A_TO_B
          );
  protected static final byte[] EXPECTED_TRANSFER_ACCESS_RESPONSE_SIGNED_BYTES_A_TO_B_TO_C_TO_D = 
      parseHex("02"                                                             // Control Byte
          + "795245b0"                                                          // Counter
          + "a29b17a9489f0eb88002659c9629df6d2d1ef94498d028322477bf3ad77bcfca"  // SERVER_CHALLENGE_SIGN
          + "9b31362dc861c620da55569e7e493d9858d2cb8ec5fc33b75bf809610aee5523"  // New Key Handle(D)
          + "5a7f496a803099a3c4f7e288cfa74a2b7f0fffcf70bb4396b7abf4841c46303d"
          + "5e7885aa14d8aafa5c2e8e97a04471d18b260bca4d26834a43cab5e112bf557f"  // Sha256 of TRANSFER_ACCESS_MESSAGE_C_TO_D
          );
  protected static final byte[] TRANSFER_ACCESS_MESSAGE_SIGNATURE_USING_AUTHENTICATION_KEY_A_TO_B =
      parseHex("30450221008739a7dd67973a270a34081261c9d30048163174fca0e80c14ff72"
          + "e449128303022010d1b8edf71fc53814b363582c93fb66306baee74a06eb4f9b"
          + "1f06d7956aebca");
  protected static final byte[] TRANSFER_ACCESS_MESSAGE_SIGNATURE_USING_ATTESTATION_KEY_A_TO_B = 
      parseHex("3045022038aa3cedbb2c5b59349031071130894fee62a2dbd9553c063ced4b77"
          + "868c0a23022100bb60d474eb4e0e4bcf65d20142ab3c8ce7438779e2b2878ef8"
          + "8bb0acb607172e");
  protected static final byte[] TRANSFER_ACCESS_MESSAGE_SIGNATURE_USING_AUTHENTICATION_KEY_C_TO_D =
      parseHex("30450221009c26611bd6ccc27d1925c64d9ee9f28483de46e36df47c7a709cf7"
          + "b3490cde1902202620c2ddf59176f749a5f9566d5928e7dd1ca72166ca78ad6d"
          + "90c0b1e330ca59");
  protected static final byte[] TRANSFER_ACCESS_MESSAGE_SIGNATURE_USING_ATTESTATION_KEY_C_TO_D = 
      parseHex("3046022100fa805fe66e7d415c0299c66d2ba8a211c4af102fad1628e66017b8"
          + "6eabb97c36022100f37f49ad0084cc7b934abd9e1fc327d0964ba351ce4b6dca"
          + "8e2a6e8c0aa4013b"
          );
  protected static final byte[] TRANSFER_ACCESS_RESPONSE_SIGNATURE_A_TO_B = 
      parseHex("3046022100fe66adfae4e95773d4deee14fda48cdd12a3343d65c1237166a6e3"
          + "f164575f17022100b5a9e6d34e5644817cc5f3478bd5940d66b089e449db57c4"
          + "e2a14bbfcf593932"
          );
  protected static final byte[] TRANSFER_ACCESS_RESPONSE_SIGNATURE_A_TO_B_TO_C_TO_D =
      parseHex("3046022100947c47239a4fe51b406e1df077c3fbc3bf9add8d1202e2cf7d3ec1"
          + "bdfa41ced80221008ce7f4c529e7396e079456e56e70ec101a3d5bcb9b53e986"
          + "33abd0055c06180e"
          );

  // Test vectors provided by Discretix
  protected static final String APP_ID_2 = APP_ID_ENROLL;
  protected static final String CHALLENGE_2_BASE64 = SERVER_CHALLENGE_ENROLL_BASE64;
  protected static final String BROWSER_DATA_2_BASE64 = BROWSER_DATA_ENROLL_BASE64;

  protected static final String TRUSTED_CERTIFICATE_2_HEX =
      "308201443081eaa0030201020209019189ffffffff5183300a06082a8648ce3d"
      + "040302301b3119301706035504031310476e756262792048534d204341203030"
      + "3022180f32303132303630313030303030305a180f3230363230353331323335"
      + "3935395a30303119301706035504031310476f6f676c6520476e756262792076"
      + "3031133011060355042d030a00019189ffffffff51833059301306072a8648ce"
      + "3d020106082a8648ce3d030107034200041f1302f12173a9cbea83d06d755411"
      + "e582a87fbb5850eddcf3607ec759a4a12c3cb392235e8d5b17caee1b34e5b5eb"
      + "548649696257f0ea8efb90846f88ad5f72300a06082a8648ce3d040302034900"
      + "3046022100b4caea5dc60fbf9f004ed84fc4f18522981c1c303155c08274e889"
      + "f3f10c5b23022100faafb4f10b92f4754e3b08b5af353f78485bc903ece7ea91"
      + "1264fc1673b6598f";
  protected static final X509Certificate TRUSTED_CERTIFICATE_2 =
      parseCertificate(TRUSTED_CERTIFICATE_2_HEX);

  // Has Bluetooth Radio transport
  private static final String TRUSTED_CERTIFICATE_ONE_TRANSPORT_BASE64 =
      "MIIBmjCCAUCgAwIBAgIJASJCAAJVliZXMAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT"
      + "AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn"
      + "aXRzIFB0eSBMdGQwIBcNMTUwODA1MTY1MTEyWhgPMjA2MzA2MDcxNjUxMTJaMEUx"
      + "CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl"
      + "cm5ldCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQu"
      + "CXRfbg9BKnqEs2frC43LSmHR+jNrvs/jC9CiyPr3RzSoL8A0ElifTMEH+TLTFn6W"
      + "HrZkwwgDR+UFYmwdXRXPoxcwFTATBgsrBgEEAYLlHAIBAQQEAwIHgDAKBggqhkjO"
      + "PQQDAgNIADBFAiAhBuNou+L8n4aZGCa5ClHGlLkPt8AZReepUx5LZTFaxQIhAKqO"
      + "daBx5kUAA3YVDH+u8bilfLS9QXKcKNm5vsdE67RJ";
  protected static final X509Certificate TRUSTED_CERTIFICATE_ONE_TRANSPORT =
      parseCertificateBase64(TRUSTED_CERTIFICATE_ONE_TRANSPORT_BASE64);

  // Has Bluetooth Radio, Bluetooth Low Energy, and NFC transports
  private static final String TRUSTED_CERTIFICATE_MULTIPLE_TRANSPORTS_BASE64 =
      "MIIBmTCCAUCgAwIBAgIJASJCAAJVliZXMAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT"
      + "AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn"
      + "aXRzIFB0eSBMdGQwIBcNMTUwODA1MTY0OTI0WhgPMjA2MzA2MDcxNjQ5MjRaMEUx"
      + "CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl"
      + "cm5ldCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQu"
      + "CXRfbg9BKnqEs2frC43LSmHR+jNrvs/jC9CiyPr3RzSoL8A0ElifTMEH+TLTFn6W"
      + "HrZkwwgDR+UFYmwdXRXPoxcwFTATBgsrBgEEAYLlHAIBAQQEAwIE0DAKBggqhkjO"
      + "PQQDAgNHADBEAiBYtS8gXcl3LhvvkVlzYJgpD/tYUHae/Rw3z8lxQSeeXwIgDE2R"
      + "yWxFfRpgeg0WsLVHu7Ll4oZUkBEuS5RgezrcrRg=";
  protected static final X509Certificate TRUSTED_CERTIFICATE_MULTIPLE_TRANSPORTS =
      parseCertificateBase64(TRUSTED_CERTIFICATE_MULTIPLE_TRANSPORTS_BASE64);

  private static final String TRUSTED_CERTIFICATE_MALFORMED_TRANSPORTS_EXTENSION_BASE64 =
      "MIIBmDCCAT6gAwIBAgIJASJCAAJVliZXMAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT"
      + "AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn"
      + "aXRzIFB0eSBMdGQwIBcNMTUwODA2MjMzNTI4WhgPMjA2MzA2MDgyMzM1MjhaMEUx"
      + "CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl"
      + "cm5ldCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQu"
      + "CXRfbg9BKnqEs2frC43LSmHR+jNrvs/jC9CiyPr3RzSoL8A0ElifTMEH+TLTFn6W"
      + "HrZkwwgDR+UFYmwdXRXPoxUwEzARBgsrBgEEAYLlHAIBAQQCqoAwCgYIKoZIzj0E"
      + "AwIDSAAwRQIhAJB/ll8z2FeYKznZ9MIsy0pjNZ/BCq8IqBmXwOBLc9ybAiBPRdVW"
      + "ri6nGl/fpka1FlhNrahJVKXYudJ72wQeibIWtg==";
  protected static final X509Certificate TRUSTED_CERTIFICATE_MALFORMED_TRANSPORTS_EXTENSION =
      parseCertificateBase64(TRUSTED_CERTIFICATE_MALFORMED_TRANSPORTS_EXTENSION_BASE64);

  private static final String ANDROID_KEYSTORE_ATTESTATION_CERT_NO_VERSION_BASE64 =
      "MIIBlzCCAQCgAwIBAgICJxAwDQYJKoZIhvcNAQELBQAwHDEaMBgGA1UEAwwRQW5kcm9pZCBLZXlt"
      + "YXN0ZXIwHhcNNzAwMTAxMDAwMDAwWhcNNzAwMTAxMDI0NjQwWjAaMRgwFgYDVQQDDA9BIEtleW1h"
      + "c3RlciBLZXkwOjANBgkqhkiG9w0BAQEFAAMpADAmAiEAvKVptjTyP1p0L8rF/XANRuIc/TOmDiBc"
      + "yb0lMri0YpkCAQOjUDBOMEwGCisGAQQB1nkCAREEPjA8MDihBgIBAgIBA4IBAYMCAQClAwIBAKYD"
      + "AgEBn4FIAQOfg3gBAZ+DeQIBLJ+FPQYBUqVEtxCfhT4BADAAMA0GCSqGSIb3DQEBCwUAA4GBAHwH"
      + "DZvsYbkgWAPv7QRa+cxLrFxrmv7M3HxYL7UdbpXP5/5sOp3hkhBdtAwlUW9tgGLdjheFFcz0lUSP"
      + "uK5et199s1ifeNzV4fePlBAGvzKFci6adJgGDMXDodM49jhIEF1KC4xlbwBWR/brl4vZa4h1EZ9H"
      + "ghyoJ3PFFZC8xYOB";
  protected static final X509Certificate ANDROID_KEYSTORE_ATTESTATION_CERT_NO_VERSION =
      parseCertificateBase64(ANDROID_KEYSTORE_ATTESTATION_CERT_NO_VERSION_BASE64);

  /**
   * Contains a chain where:
   *   cert[0] = attestation certificate describing some new key
   *   cert[1] = batch certificate
   *
   * Note that cert[1] is signed by another cert that should be known to RPs.
   */
  private static final String ANDROID_KEYSTORE_ATTESTATION_CERT_CHAIN_BASE64 =
      "MIIBjTCCATKgAwIBAgICJxAwCgYIKoZIzj0EAwIwHDEaMBgGA1UEAwwRQW5kcm9pZCBLZXltYXN0"
      + "ZXIwIBcNNzAwMTAxMDAwMDAwWhgPMjEwNjAyMDcwNjI4MTVaMBoxGDAWBgNVBAMMD0EgS2V5bWFz"
      + "dGVyIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJiTI/rSw9N1NYV3FGxgeJSj1NWyyb61"
      + "/gbdEefKuM3dYOeUZhciSigDY/u9Y3gBKm0wmXsd7DxXibDk/VvGIVWjZDBiMGAGCisGAQQB1nkC"
      + "AREEUjBQAgECBAljaGFsbGVuZ2UwPqEIMQYCAQICAQOiAwIBA6MEAgIBAKUFMQMCAQS/g3gDAgEB"
      + "v4N5BAICASy/hT0IAgYBUqi8MmC/hT4DAgEAMAAwCgYIKoZIzj0EAwIDSQAwRgIhANnmsSeWsnVH"
      + "aF5zII50tkiA7fRhIMNeZZBcPvSV2BN5AiEAwUZm63OxMZEHTIFL50ASKVN/sCLs8+gMY6uEVZRy"
      + "61QwggK2MIICH6ADAgECAgIQADANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJVUzETMBEGA1UE"
      + "CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMGA1UECgwMR29vZ2xlLCBJ"
      + "bmMuMRAwDgYDVQQLDAdBbmRyb2lkMB4XDTE2MDEwNDEyNDA1M1oXDTM1MTIzMDEyNDA1M1owdjEL"
      + "MAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQ"
      + "MA4GA1UECwwHQW5kcm9pZDEpMCcGA1UEAwwgQW5kcm9pZCBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBL"
      + "ZXkwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMCDI9xWiBu4MCBp9bCFYcbuvn8F4vWoQgSK"
      + "votHvnb+rvJc8psq+jIAFBYBQpmJoV/PxoFes2NYPC/S8gvkmDKD3YFLFtfhhUF65Uq8KWo6bbXA"
      + "BAg7aMVWwfAjOZFkGYZNULdNQK7KSEx3NWyJWgwnWr+sSZ1dfSNi8pxeAuhxAgMBAAGjZjBkMB0G"
      + "A1UdDgQWBBTUDBAb+M1jufc5UrUOE1ym15mThjAfBgNVHSMEGDAWgBQp+vGszE3STJZAJ3W2sOky"
      + "5Qf+LjASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIChDANBgkqhkiG9w0BAQsFAAOB"
      + "gQCeLUhfjGcz3BqFrZnXUCPqFOxDsOGd6sIjRh5ytRncYCLkpWgxbAtVxOacoi2fOk+TazGLFngW"
      + "DYjL2YvMgJ2E8MIn42s48f3R5xdyMVk1fZbzxX+rnY+WYSZPsr6Buw1JBCKKzp/39UIuJUT6IQcS"
      + "WoO1Va0YgvhAFJucIGMEfw==";
  protected static final X509Certificate[] ANDROID_KEYSTORE_ATTESTATION_CERT_CHAIN =
      parseCertificateChainBase64(ANDROID_KEYSTORE_ATTESTATION_CERT_CHAIN_BASE64);

  protected static final byte[] REGISTRATION_DATA_2 =
      parseHex("0504478E16BBDBBB741A660A000314A8B6BD63095196ED704C52EEBC0FA02A61"
          + "8F19FF59DF18451A11CEE43DEFD9A29B5710F63DFC671F752B1B0C6CA76C8427"
          + "AF2D403C2415E1760D1108105720C6069A9039C99D09F76909C36D9EFC350937"
          + "31F85F55AC6D73EA69DE7D9005AE9507B95E149E19676272FC202D949A3AB151"
          + "B96870308201443081EAA0030201020209019189FFFFFFFF5183300A06082A86"
          + "48CE3D040302301B3119301706035504031310476E756262792048534D204341"
          + "2030303022180F32303132303630313030303030305A180F3230363230353331"
          + "3233353935395A30303119301706035504031310476F6F676C6520476E756262"
          + "7920763031133011060355042D030A00019189FFFFFFFF51833059301306072A"
          + "8648CE3D020106082A8648CE3D030107034200041F1302F12173A9CBEA83D06D"
          + "755411E582A87FBB5850EDDCF3607EC759A4A12C3CB392235E8D5B17CAEE1B34"
          + "E5B5EB548649696257F0EA8EFB90846F88AD5F72300A06082A8648CE3D040302"
          + "0349003046022100B4CAEA5DC60FBF9F004ED84FC4F18522981C1C303155C082"
          + "74E889F3F10C5B23022100FAAFB4F10B92F4754E3B08B5AF353F78485BC903EC"
          + "E7EA911264FC1673B6598F3046022100F3BE1BF12CBF0BE7EAB5EA32F3664EDB"
          + "18A24D4999AAC5AA40FF39CF6F34C9ED022100CE72631767367467DFE2AECF6A"
          + "5A4EBA9779FAC65F5CA8A2C325B174EE4769AC");
  protected static final String REGISTRATION_DATA_2_BASE64 =
      Base64.encodeBase64URLSafeString(REGISTRATION_DATA_2);
  protected static final byte[] KEY_HANDLE_2 =
      parseHex("3c2415e1760d1108105720c6069a9039c99d09f76909c36d9efc35093731f85f"
          + "55ac6d73ea69de7d9005ae9507b95e149e19676272fc202d949a3ab151b96870");
  protected static final String KEY_HANDLE_2_BASE64 =
      Base64.encodeBase64URLSafeString(KEY_HANDLE_2);
  protected static final byte[] USER_PUBLIC_KEY_2 =
      parseHex("04478e16bbdbbb741a660a000314a8b6bd63095196ed704c52eebc0fa02a618f"
          + "19ff59df18451a11cee43defd9a29b5710f63dfc671f752b1b0c6ca76c8427af"
          + "2d");
  protected static final byte[] SIGN_DATA_2 =
      parseHex("01000000223045022100FB16D12F8EC73D93EAB43BFDF141BF94E31AD3B1C98E"
          + "E4459E9E80CBBBD892F70220796DBCB8BBF57EC95A20A76D9ED3365CB688BF88"
          + "2ECCEABCC8D4A674024F6ABA");
  protected static final String SIGN_DATA_2_BASE64 = Base64.encodeBase64URLSafeString(SIGN_DATA_2);
}
