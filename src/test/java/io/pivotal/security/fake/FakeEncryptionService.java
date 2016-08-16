package io.pivotal.security.fake;

import io.pivotal.security.service.AbstractEncryptionService;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

@Service
@Primary
@Profile("FakeEncryptionService")
public class FakeEncryptionService extends AbstractEncryptionService {

  private int count = 0;

  @Override
  public Encryption encrypt(String value) {
    count++;
    return new Encryption("4".getBytes(), ("SECRET"+value).getBytes());
  }

  @Override
  public String decrypt(byte[] nonce, byte[] encryptedValue) {
    Assert.notNull(nonce, "nonce is required");
    return new String(encryptedValue).substring(6);
  }

  public int getCount() {
    return count;
  }

  public void setCount(int count) {
    this.count = count;
  }
}
