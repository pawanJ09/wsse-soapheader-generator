package com.digest;

import static java.lang.System.currentTimeMillis;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

/**
 * This class is used to generate the WSSE Security Header with Password digest based on 16 byte
 * nonce using SHA-1 and Base64 encoding the password.
 *
 * @author - Pawan Jaiswal
 */
public class WssePasswordDigestGenerator {

  private static final SecureRandom RANDOM;
  private static final int NONCE_SIZE_IN_BYTES = 16;
  private static final String MESSAGE_DIGEST_ALGORITHM_NAME_SHA_1 = "SHA-1";
  private static final String SECURE_RANDOM_ALGORITHM_SHA_1_PRNG = "SHA1PRNG";

  static {
    try {
      RANDOM = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM_SHA_1_PRNG);
      RANDOM.setSeed(currentTimeMillis());
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * main method for the project.
   *
   * @param args runtime String arguments
   * @throws DatatypeConfigurationException Exception
   */
  public static void main(String[] args) throws DatatypeConfigurationException {
    String username = "wsapi3_user";
    String password = "wsapi3_pass";
    generateHeader(username, password);
  }

  /**
   * This method generates the WSSE Security header and prints in pretty format.
   *
   * @param username The user id to authenticate
   * @param password The password to authenticate with
   * @throws DatatypeConfigurationException Exception for XMLGregorianCalendar
   */
  public static void generateHeader(String username, String password)
      throws DatatypeConfigurationException {
    final byte[] nonceBytes = generateNonce();
    final XMLGregorianCalendar createdDate = DatatypeFactory.newInstance()
        .newXMLGregorianCalendar(Instant.now().toString());
    final byte[] passwordDigestBytes = constructPasswordDigest(nonceBytes, createdDate, password);
    final Base64.Encoder base64Encoder = Base64.getEncoder();
    final String nonceBase64Encoded = base64Encoder.encodeToString(nonceBytes);
    final String passwordDigestBase64Encoded = base64Encoder.encodeToString(passwordDigestBytes);
    StringBuilder sb = new StringBuilder();
    sb.append("<soapenv:Header>\n");
    sb.append("\t<wsse:Security xmlns:wsse=\"http://docs.oasis-open"
                  + ".org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">\n");
    sb.append("\t\t<wsse:UsernameToken>\n");
    sb.append("\t\t\t<wsse:Username>" + username + "</wsse:Username>\n");
    sb.append("\t\t\t<wsse:Password Type=\"http://docs.oasis-open"
                  + ".org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">"
                  + passwordDigestBase64Encoded + "</wsse:Password>\n");
    sb.append("\t\t\t<wsse:Nonce EncodingType=\"http://docs.oasis-open"
                  + ".org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">"
                  + nonceBase64Encoded + "</wsse:Nonce>\n");
    sb.append("\t\t\t<wsu:Created xmlns:wsu=\"http://docs.oasis-open"
                  + ".org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
                  + createdDate.toString() + "</wsu:Created>\n");
    sb.append("\t\t</wsse:UsernameToken>\n");
    sb.append("\t</wsse:Security>\n");
    sb.append("</soapenv:Header>");

    System.out.println(sb.toString());
    System.out.flush();
    System.exit(0);
  }

  /**
   * Generates the 16 byte nonce.
   *
   * @return nonce bytes
   */
  private static byte[] generateNonce() {
    byte[] nonceBytes = new byte[NONCE_SIZE_IN_BYTES];
    RANDOM.nextBytes(nonceBytes);
    return nonceBytes;
  }

  /**
   * Generates the password digest in bytes using nonce, createdDate and password.
   *
   * @param nonceBytes generated nonce in bytes
   * @param createdDate XMLGregorianCalendar
   * @param password String
   * @return passwordDigest bytes
   */
  private static byte[] constructPasswordDigest(byte[] nonceBytes, XMLGregorianCalendar createdDate,
                                                String password) {
    try {
      final MessageDigest sha1MessageDigest =
          MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM_NAME_SHA_1);
      sha1MessageDigest.update(nonceBytes);
      final String createdDateAsString = createdDate.toString();
      sha1MessageDigest.update(createdDateAsString.getBytes(UTF_8));
      sha1MessageDigest.update(password.getBytes(UTF_8));
      return sha1MessageDigest.digest();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

}