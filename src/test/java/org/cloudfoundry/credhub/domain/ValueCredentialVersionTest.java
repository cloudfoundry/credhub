package org.cloudfoundry.credhub.domain;

import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.UUID;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class ValueCredentialVersionTest {

  private ValueCredentialVersion subject;
  private Encryptor encryptor;
  private UUID canaryUuid;
  private ValueCredentialVersionData valueCredentialData;

  @Before
  public void beforeEach() {
    canaryUuid = UUID.randomUUID();
    encryptor = mock(Encryptor.class);
    byte[] encryptedValue = "fake-encrypted-value".getBytes();
    byte[] nonce = "fake-nonce".getBytes();
    final EncryptedValue encryption = new EncryptedValue(canaryUuid, encryptedValue, nonce);
    when(encryptor.encrypt("my-value"))
        .thenReturn(encryption);
    when(encryptor.decrypt(encryption))
        .thenReturn("my-value");

    subject = new ValueCredentialVersion("Foo");
  }

  @Test
  public void getCredentialType_returnsCorrectType() {
    assertThat(subject.getCredentialType(), equalTo("value"));
  }

  @Test
  public void setValue_encryptsValue() {
    valueCredentialData = new ValueCredentialVersionData("foo");
    subject = new ValueCredentialVersion(valueCredentialData).setEncryptor(encryptor);

    subject.setValue("my-value");

    assertThat(valueCredentialData.getEncryptedValueData().getEncryptedValue(), notNullValue());
    assertThat(valueCredentialData.getEncryptedValueData().getNonce(), notNullValue());
  }

  @Test
  public void getValue_decryptsValue() {
    valueCredentialData = new ValueCredentialVersionData("foo");
    subject = new ValueCredentialVersion(valueCredentialData).setEncryptor(encryptor);

    subject.setValue("my-value");

    assertThat(subject.getValue(), equalTo("my-value"));
  }

  @Test(expected = IllegalArgumentException.class)
  public void setValue_whenValueIsNull_throwsException() {
    valueCredentialData = new ValueCredentialVersionData("foo");
    subject = new ValueCredentialVersion(valueCredentialData).setEncryptor(encryptor);

    subject.setValue(null);
  }
}
