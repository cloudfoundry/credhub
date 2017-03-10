package io.pivotal.security.entity;

import io.pivotal.security.view.SecretKind;
import org.apache.commons.codec.binary.Base64;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.math.BigInteger;
import java.util.Arrays;

@Entity
@Table(name = "SshSecret")
@DiscriminatorValue(NamedSshSecretData.SECRET_TYPE)
public class NamedSshSecretData extends NamedSecretData<NamedSshSecretData> {
  public static final String SECRET_TYPE = "ssh";

  @Column(length = 7000)
  private String publicKey;

  public NamedSshSecretData() {
    this(null);
  }

  public NamedSshSecretData(String name) {
    super(name);
  }

  public String getPublicKey() {
    return publicKey;
  }

  public NamedSshSecretData setPublicKey(String publicKey) {
    this.publicKey = publicKey;
    return this;
  }

  @Override
  public void copyIntoImpl(NamedSshSecretData copy) {
    copy.setPublicKey(getPublicKey());
  }

  public SecretKind getKind() {
    return SecretKind.SSH;
  }

  @Override
  public String getSecretType() {
    return SECRET_TYPE;
  }

  public int getKeyLength() {
    return parsePublicKey().keyLength;
  }

  public String getComment() {
    return parsePublicKey().comment;
  }

  private ParsedPublicKeyValues parsePublicKey() {
    // https://www.ietf.org/rfc/rfc4253.txt - section 6.6
    // we are parsing the key which consists of multiple precision integers to derive modulus and hence key length
    String publicKey = getPublicKey();
    ParsedPublicKeyValues values = new ParsedPublicKeyValues();

    int endOfPrefix = publicKey.indexOf(' ') + 1;
    int startOfComment = publicKey.indexOf(' ', endOfPrefix);
    String isolatedPublicKey;
    if (startOfComment != -1) {
      isolatedPublicKey = publicKey.substring(endOfPrefix, startOfComment);
      values.comment = publicKey.substring(startOfComment + 1);
    } else {
      isolatedPublicKey = publicKey.substring(endOfPrefix);
      values.comment = "";
    }

    DataInputStream dataStream = new DataInputStream(new ByteArrayInputStream(Base64.decodeBase64(isolatedPublicKey)));

    readType(dataStream);
    readExponent(dataStream);
    values.keyLength = readKeyLength(dataStream);

    return values;
  }

  private byte[] readType(DataInputStream dataStream) {
    return readBytesFrom(dataStream);
  }

  private byte[] readExponent(DataInputStream dataStream) {
    return readBytesFrom(dataStream);
  }

  private int readKeyLength(DataInputStream dataStream) {
    byte[] buf = readBytesFrom(dataStream);
    BigInteger modulus = new BigInteger(Arrays.copyOf(buf, buf.length));
    // calculate key length
    return modulus.bitLength();
  }

  private byte[] readBytesFrom(DataInputStream dataStream) {
    byte[] buf;
    try {
      int length = dataStream.readInt();
      buf = new byte[length];
      dataStream.read(buf, 0, length);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    return buf;
  }

  private static class ParsedPublicKeyValues {
    int keyLength;
    String comment;
  }
}
