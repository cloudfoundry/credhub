package io.pivotal.security.fake;

import io.pivotal.security.service.EncryptionService;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

@Service
@Primary
@Profile("FakeEncryptionService")
public class FakeEncryptionService implements EncryptionService {

  private int encryptionCount = 0;
  private int decryptionCount = 0;

  @Override
  public Encryption encrypt(String value) {
    encryptionCount++;
    return new Encryption(String.valueOf(encryptionCount).getBytes(), ("SECRET"+value).getBytes());
  }

  @Override
  public String decrypt(byte[] nonce, byte[] encryptedValue) {
    decryptionCount++;
    Assert.notNull(nonce, "nonce is required");
    return new String(encryptedValue).substring(6);
  }

  public int getEncryptionCount() {
    return encryptionCount;
  }

  public void setEncryptionCount(int encryptionCount) {
    this.encryptionCount = encryptionCount;
  }

  public int getDecryptionCount() {
    return decryptionCount;
  }

  public void setDecryptionCount(int decryptionCount) {
    this.decryptionCount = decryptionCount;
  }
}
