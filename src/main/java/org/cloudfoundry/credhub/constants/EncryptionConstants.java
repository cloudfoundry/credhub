package org.cloudfoundry.credhub.constants;

public class EncryptionConstants {

  public static final int NONCE_SIZE = 12;
  public static final int ENCRYPTED_BYTES = 7000;
  public static final int SALT_SIZE = 64;
  public static final int KEY_BIT_LENGTH = 256;
  public static final int ITERATIONS = 100000;
}
