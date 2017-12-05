package org.cloudfoundry.credhub.domain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.entity.JsonCredentialVersionData;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static junit.framework.TestCase.fail;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class JsonCredentialVersionTest {

  private JsonCredentialVersion subject;
  private Map<String, Object> value;

  private JsonCredentialVersionData jsonCredentialData;

  @Before
  public void beforeEach() throws JsonProcessingException {
    Map<String, Object> nested = new HashMap<>();
    nested.put("key", "value");

    value = new HashMap<>();
    value.put("simple", "just-a-string");
    value.put("complex", nested);

    String serializedValue = new ObjectMapper().writeValueAsString(value);

    Encryptor encryptor = mock(Encryptor.class);
    byte[] encryptedValue = "fake-encrypted-value".getBytes();
    byte[] nonce = "fake-nonce".getBytes();
    UUID canaryUuid = UUID.randomUUID();
    final EncryptedValue encryption = new EncryptedValue(canaryUuid, encryptedValue, nonce);
    when(encryptor.encrypt(serializedValue))
        .thenReturn(encryption);
    when(encryptor.decrypt(encryption))
        .thenReturn(serializedValue);

    jsonCredentialData = new JsonCredentialVersionData("Foo");
    subject = new JsonCredentialVersion(jsonCredentialData).setEncryptor(encryptor);
  }

  @Test
  public void getCredentialType_returnsCorrectType() {
    assertThat(subject.getCredentialType(), equalTo("json"));
  }

  @Test
  public void setValue_setsEncryptedValueAndNonce() {
    subject.setValue(value);

    assertThat(jsonCredentialData.getEncryptedValueData().getEncryptedValue(), notNullValue());
    assertThat(jsonCredentialData.getNonce(), notNullValue());
  }

  @Test
  public void getValue_decryptsValue() {
    subject.setValue(value);

    assertThat(subject.getValue(), equalTo(value));
  }

  @Test
  public void setValue_whenValueIsNull_throwsException() {
    try {
      subject.setValue((Map) null);
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.missing_value"));
    }
  }
}
