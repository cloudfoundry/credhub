package io.pivotal.security.entity;

public class SecretEncryptionHelperProvider {
  public static SecretEncryptionHelper getInstance() {
    return BeanStaticProvider.getInstance(SecretEncryptionHelper.class);
  }
}
