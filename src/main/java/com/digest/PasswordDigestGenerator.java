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
 * This class is used to generate the Password digest based on 16 byte nonce using SHA-1 and Base64
 * encoding the password.
 *
 * @author - Pawan Jaiswal
 */
public class PasswordDigestGenerator {
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
   * main method for the file.
   *
   * @param args runtime String arguments
   * @throws DatatypeConfigurationException Exception
   */
  public static void main(String[] args) throws DatatypeConfigurationException {
    final var nonceBytes = generateNonce();
    final var password = "wsapi3_pass";
    final XMLGregorianCalendar createdDate =
        DatatypeFactory.newInstance().newXMLGregorianCalendar(Instant.now().toString());
    final var passwordDigestBytes = constructPasswordDigest(
        nonceBytes, createdDate, password);
    final var base64Encoder = Base64.getEncoder();
    final var nonceBase64Encoded = base64Encoder.encodeToString(nonceBytes);
    final var passwordDigestBase64Encoded = base64Encoder
        .encodeToString(passwordDigestBytes);
    System.out.println(String.format("nonce: [%s], password digest: [%s]", nonceBase64Encoded,
                                     passwordDigestBase64Encoded));
    System.out.flush();
  }

  /**
   * Generates the 16 byte nonce.
   *
   * @return nonce bytes
   */
  private static byte[] generateNonce() {
    var nonceBytes = new byte[NONCE_SIZE_IN_BYTES];
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
  private static byte[] constructPasswordDigest(
      byte[] nonceBytes, XMLGregorianCalendar createdDate, String password) {
    try {
      final var sha1MessageDigest = MessageDigest
          .getInstance(MESSAGE_DIGEST_ALGORITHM_NAME_SHA_1);
      sha1MessageDigest.update(nonceBytes);
      final var createdDateAsString = createdDate.toString();
      sha1MessageDigest.update(createdDateAsString.getBytes(UTF_8));
      sha1MessageDigest.update(password.getBytes(UTF_8));
      return sha1MessageDigest.digest();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

}
