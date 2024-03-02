package org.cloudfoundry.credhub.entities;

import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsEqual.equalTo;

public class CredentialVersionDataTest {

  private PasswordCredentialVersionData passwordCredentialData;

  @BeforeEach
  public void beforeEach() {
    passwordCredentialData = new PasswordCredentialVersionData("/Picard");
  }

  @Test
  public void encryptedValue_doesNotStoreOrPassByReference() throws Exception {
    final byte[] toModify = "foobar".getBytes(UTF_8);

    final EncryptedValue encryptedValue = new EncryptedValue();
    encryptedValue.setEncryptedValue(toModify);

    passwordCredentialData.setEncryptedValueData(encryptedValue);
    final byte[] unModified = toModify.clone();

    toModify[0] = (byte) 'a';

    assertThat(passwordCredentialData.getEncryptedValueData().getEncryptedValue(), not(equalTo(toModify)));
    assertThat(passwordCredentialData.getEncryptedValueData().getEncryptedValue(), equalTo(unModified));
  }

  @Test
  public void nonce_doesNotStoreOrPassByReference() throws Exception {
    final byte[] toModify = "foobar".getBytes(UTF_8);
    final EncryptedValue encryptedValue = new  EncryptedValue();
    encryptedValue.setEncryptedValue(toModify);
    encryptedValue.setNonce(toModify);

    passwordCredentialData.setEncryptedValueData(encryptedValue);
    final byte[] unModified = toModify.clone();

    toModify[0] = (byte) 'a';

    assertThat(passwordCredentialData.getEncryptedValueData().getNonce(), not(equalTo(toModify)));
    assertThat(passwordCredentialData.getEncryptedValueData().getNonce(), equalTo(unModified));
  }
}
