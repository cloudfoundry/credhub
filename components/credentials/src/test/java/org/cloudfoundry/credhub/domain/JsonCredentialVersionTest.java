package org.cloudfoundry.credhub.domain;

import java.io.IOException;
import java.util.UUID;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.entity.JsonCredentialVersionData;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.utils.StringUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static junit.framework.TestCase.fail;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class JsonCredentialVersionTest {

  private JsonCredentialVersion subject;
  private JsonNode value;

  private JsonCredentialVersionData jsonCredentialData;

  @Before
  public void beforeEach() throws JsonProcessingException {
    final String jsonString = "{\"simple\":\"just-a-string\",\"complex\":{\"key\":\"value\"}}";
    final ObjectMapper objectMapper = new ObjectMapper();
    final String serializedValue;

    try {
      value = objectMapper.readTree(jsonString);
      serializedValue = objectMapper.writeValueAsString(value);
    } catch (final IOException e) {
      throw new RuntimeException(e);
    }

    final Encryptor encryptor = mock(Encryptor.class);
    final byte[] encryptedValue = "fake-encrypted-value".getBytes(StringUtil.UTF_8);
    final byte[] nonce = "fake-nonce".getBytes(StringUtil.UTF_8);
    final UUID canaryUuid = UUID.randomUUID();
    final EncryptedValue encryption = new EncryptedValue(canaryUuid, encryptedValue, nonce);
    when(encryptor.encrypt(serializedValue))
      .thenReturn(encryption);
    when(encryptor.decrypt(encryption))
      .thenReturn(serializedValue);

    jsonCredentialData = new JsonCredentialVersionData("Foo");
    subject = new JsonCredentialVersion(jsonCredentialData);
    subject.setEncryptor(encryptor);
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
      subject.setValue((JsonNode) null);
      fail("should throw");
    } catch (final ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.missing_value"));
    }
  }
}
