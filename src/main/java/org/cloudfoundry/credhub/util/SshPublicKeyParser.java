package org.cloudfoundry.credhub.util;

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Base64;

public class SshPublicKeyParser {

  private String publicKey;
  private String fingerprint;
  private String comment;
  private int keyLength;
  private Base64.Encoder encoder = Base64.getEncoder().withoutPadding();
  private Base64.Decoder decoder = Base64.getDecoder();

  public SshPublicKeyParser() {}

  public void setPublicKey(String publicKey) {
    if (this.publicKey != null) {
      return;
    }

    this.publicKey = publicKey != null ? publicKey.trim() : null;
    parsePublicKey();
  }

  public String getFingerprint() {
    return fingerprint;
  }

  public String getComment() {
    return comment;
  }

  public int getKeyLength() {
    return keyLength;
  }

  // https://www.ietf.org/rfc/rfc4253.txt - section 6.6
  // we are parsing the key which consists of multiple precision integers to
  // derive modulus and hence key length
  private void parsePublicKey() {
    if (publicKey == null) {
      return;
    }

    int endOfPrefix = publicKey.indexOf(' ') + 1;
    if (endOfPrefix == 0) {
      return;
    } // invalid format, does not have ssh- prefix.

    int startOfComment = publicKey.indexOf(' ', endOfPrefix);

    String isolatedPublicKey;

    if (startOfComment != -1) {
      isolatedPublicKey = publicKey.substring(endOfPrefix, startOfComment);
      comment = publicKey.substring(startOfComment + 1);
    } else {
      isolatedPublicKey = publicKey.substring(endOfPrefix);
      comment = "";
    }

    if (isolatedPublicKey.equals("")) {
      comment = null;
      return;
    }

    try {
      byte[] decodedIsolatedPublicKey = decoder.decode(isolatedPublicKey);
      fingerprint = fingerprintOf(decodedIsolatedPublicKey);

      DataInputStream dataStream = new DataInputStream(
          new ByteArrayInputStream(decodedIsolatedPublicKey)
      );

      readAndRemoveType(dataStream);
      readAndRemoveExponent(dataStream);
      keyLength = readAndRemoveKeyLength(dataStream);
    } catch (Exception e) {
      comment = null;
      fingerprint = null;
      keyLength = 0;
    }
  }

  private String fingerprintOf(byte[] decodedIsolatedPublicKey) {
    return encoder.encodeToString(DigestUtils.getSha256Digest().digest(decodedIsolatedPublicKey));
  }

  private byte[] readAndRemoveType(DataInputStream dataStream) throws IOException {
    return readIntAsBytesFrom(dataStream);
  }

  private byte[] readAndRemoveExponent(DataInputStream dataStream) throws IOException {
    return readIntAsBytesFrom(dataStream);
  }

  private int readAndRemoveKeyLength(DataInputStream dataStream) throws IOException {
    byte[] buf = readIntAsBytesFrom(dataStream);
    BigInteger modulus = new BigInteger(Arrays.copyOf(buf, buf.length));
    // calculate key length
    return modulus.bitLength();
  }

  private byte[] readIntAsBytesFrom(DataInputStream dataStream) throws IOException {
    byte[] buf;
    int length = dataStream.readInt();
    buf = new byte[length];

    // FindBugs exposed possible bug of not checking for correct output from InputStream
    if (dataStream.read(buf, 0, length) != length) {
      throw new IOException("Could not read int as bytes");
    }
    return buf;
  }
}
