package io.pivotal.security.entity;

class SecretEncryptionHelperProvider {
  public static SecretEncryptionHelper getInstance() {
    return BeanStaticProvider.getInstance(SecretEncryptionHelper.class);
  }
}
