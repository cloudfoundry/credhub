package io.pivotal.security.entity;

import org.junit.Before;
import org.junit.Test;

import java.util.Random;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.IsEqual.equalTo;

public class CredentialDataTest {

  private PasswordCredentialData passwordCredentialData;

  @Before
  public void beforeEach() {
    passwordCredentialData = new PasswordCredentialData("/Picard");
  }

  @Test
  public void encryptedValue_doesNotStoreOrPassByReference() throws Exception {
    byte[] toModify = new byte[20];
    new Random().nextBytes(toModify);

    passwordCredentialData.setEncryptedValue(toModify);
    byte[] unModified = toModify.clone();

    toModify[0] = (byte) 'a';

    assertThat(passwordCredentialData.getEncryptedValue(), not(equalTo(toModify)));
    assertThat(passwordCredentialData.getEncryptedValue(), equalTo(unModified));
  }

  @Test
  public void encryptedValue_returnsNullWhenEncryptedValueNull() throws Exception {
    passwordCredentialData.setEncryptedValue(null);

    assertThat(passwordCredentialData.getEncryptedValue(), nullValue());
  }

  @Test
  public void nonce_doesNotStoreOrPassByReference() throws Exception {
    byte[] toModify = new byte[20];
    new Random().nextBytes(toModify);

    passwordCredentialData.setNonce(toModify);
    byte[] unModified = toModify.clone();

    toModify[0] = (byte) 'a';

    assertThat(passwordCredentialData.getNonce(), not(equalTo(toModify)));
    assertThat(passwordCredentialData.getNonce(), equalTo(unModified));
  }

  @Test
  public void nonce_returnsNullWhenEncryptedValueNull() throws Exception {
    passwordCredentialData.setNonce(null);

    assertThat(passwordCredentialData.getNonce(), nullValue());
  }
}