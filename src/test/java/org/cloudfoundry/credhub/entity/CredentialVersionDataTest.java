package org.cloudfoundry.credhub.entity;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(JUnit4.class)
public class CredentialVersionDataTest {

  private PasswordCredentialVersionData passwordCredentialData;

  @Before
  public void beforeEach() {
    passwordCredentialData = new PasswordCredentialVersionData("/Picard");
  }

  @Test
  public void encryptedValue_doesNotStoreOrPassByReference() throws Exception {
    byte[] toModify = "foobar".getBytes();
    passwordCredentialData.setEncryptedValueData(new EncryptedValue().setEncryptedValue(toModify));
    byte[] unModified = toModify.clone();

    toModify[0] = (byte) 'a';

    assertThat(passwordCredentialData.getEncryptedValueData().getEncryptedValue(), not(equalTo(toModify)));
    assertThat(passwordCredentialData.getEncryptedValueData().getEncryptedValue(), equalTo(unModified));
  }

  @Test
  public void nonce_doesNotStoreOrPassByReference() throws Exception {
    byte[] toModify = "foobar".getBytes();
    passwordCredentialData.setEncryptedValueData(new EncryptedValue().setEncryptedValue(toModify)
        .setNonce(toModify));
    byte[] unModified = toModify.clone();

    toModify[0] = (byte) 'a';

    assertThat(passwordCredentialData.getEncryptedValueData().getNonce(), not(equalTo(toModify)));
    assertThat(passwordCredentialData.getEncryptedValueData().getNonce(), equalTo(unModified));
  }
}
