package io.pivotal.security.entity;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.Random;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(SpringJUnit4ClassRunner.class)
public class EncryptionKeyCanaryTest {

  private EncryptionKeyCanary subject;

  @Before
  public void beforeEach() {
    subject = new EncryptionKeyCanary();
  }

  @Test
  public void encryptedCanaryValue_doesNotStoreOrPassByReference() throws Exception {
    byte[] toModify = new byte[20];
    new Random().nextBytes(toModify);

    subject.setEncryptedCanaryValue(toModify);
    byte[] unModified = toModify.clone();

    toModify[0] = (byte) 'a';

    assertThat(subject.getEncryptedCanaryValue(), not(equalTo(toModify)));
    assertThat(subject.getEncryptedCanaryValue(), equalTo(unModified));
  }

  @Test
  public void encryptedCanaryValue_returnsNullWhenEncryptedValueNull() throws Exception {
    subject.setEncryptedCanaryValue(null);

    assertThat(subject.getEncryptedCanaryValue(), nullValue());
  }

  @Test
  public void nonce_doesNotStoreOrPassByReference() throws Exception {
    byte[] toModify = new byte[20];
    new Random().nextBytes(toModify);

    subject.setNonce(toModify);
    byte[] unModified = toModify.clone();

    toModify[0] = (byte) 'b';

    assertThat(subject.getNonce(), not(equalTo(toModify)));
    assertThat(subject.getNonce(), equalTo(unModified));
  }

  @Test
  public void nonce_returnsNullWhenEncryptedValueNull() throws Exception {
    subject.setNonce(null);

    assertThat(subject.getNonce(), nullValue());
  }

  @Test
  public void salt_doesNotStoreOrPassByReference() throws Exception {
    byte[] toModify = new byte[20];
    new Random().nextBytes(toModify);

    subject.setSalt(toModify);
    byte[] unModified = toModify.clone();

    toModify[0] = (byte) 'b';

    assertThat(subject.getSalt(), not(equalTo(toModify)));
    assertThat(subject.getSalt(), equalTo(unModified));
  }

  @Test
  public void salt_returnsNullWhenEncryptedValueNull() throws Exception {
    subject.setSalt(null);

    assertThat(subject.getSalt(), nullValue());
  }

  @Test
  public void setEncryptionKeyUuid_shouldSetTheUUID() {
    UUID uuid = UUID.randomUUID();

    subject.setEncryptionKeyUuid(uuid);

    assertThat(subject.getUuid(), equalTo(uuid));
  }
}