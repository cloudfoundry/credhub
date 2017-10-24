package io.pivotal.security.view;

import io.pivotal.security.credential.CryptSaltFactory;
import io.pivotal.security.domain.UserCredentialVersion;
import io.pivotal.security.helper.JsonTestHelper;
import org.apache.commons.codec.digest.Crypt;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.util.UUID;

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

    UserView actual = (UserView) UserView.fromEntity(userCredential);

    assertThat(JsonTestHelper.serializeToString(actual), equalTo("{"
        + "\"type\":\"user\","
        + "\"version_created_at\":null,"
        + "\"id\":\"" + uuid.toString() + "\","
        + "\"name\":\"/foo\","
        + "\"value\":{"
        + "\"username\":\"test-username\","
        + "\"password\":\"test-password\","
        + "\"password_hash\":\"" + passwordHash + "\""
        + "}}"));
  }
}
