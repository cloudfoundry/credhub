package org.cloudfoundry.credhub.views;

import java.io.IOException;
import java.util.UUID;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.commons.codec.digest.Crypt;
import org.cloudfoundry.credhub.CryptSaltFactory;
import org.cloudfoundry.credhub.domain.UserCredentialVersion;
import org.cloudfoundry.credhub.helpers.JsonTestHelper;
import org.cloudfoundry.credhub.utils.JsonObjectMapper;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class UserViewTest {

  @Test
  public void canCreateViewFromEntity() throws IOException {
    final UUID uuid = UUID.randomUUID();
    final String salt = new CryptSaltFactory().generateSalt("test-password");
    final String passwordHash = Crypt.crypt("test-password", salt);

    final UserCredentialVersion userCredential = mock(UserCredentialVersion.class);
    when(userCredential.getName()).thenReturn("/foo");
    when(userCredential.getUuid()).thenReturn(uuid);
    when(userCredential.getCredentialType()).thenReturn("user");
    when(userCredential.getPassword()).thenReturn("test-password");
    when(userCredential.getUsername()).thenReturn("test-username");
    when(userCredential.getSalt()).thenReturn(salt);
    JsonObjectMapper objectMapper = new JsonObjectMapper();
    JsonNode metadata = null;
    try {
      metadata = objectMapper.readTree("{\"name\":\"test\"}");
    } catch (IOException e) {
      e.printStackTrace();
    }
    when(userCredential.getMetadata()).thenReturn(metadata);

    final UserView actual = (UserView) UserView.fromEntity(userCredential);

    assertThat(JsonTestHelper.serializeToString(actual), equalTo("{"
      + "\"type\":\"user\","
      + "\"version_created_at\":null,"
      + "\"id\":\"" + uuid.toString() + "\","
      + "\"name\":\"/foo\","
      + "\"metadata\":{\"name\":\"test\"},"
      + "\"value\":{"
      + "\"username\":\"test-username\","
      + "\"password\":\"test-password\","
      + "\"password_hash\":\"" + passwordHash + "\""
      + "}}"));
  }
}
