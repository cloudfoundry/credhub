package io.pivotal.security.view;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.credential.CryptSaltFactory;
import io.pivotal.security.domain.UserCredential;
import org.apache.commons.codec.digest.Crypt;
import org.junit.runner.RunWith;

import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.json;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class UserViewTest {
  {
    it("can create view from entity", () -> {
      final UUID uuid = UUID.randomUUID();
      final String salt = new CryptSaltFactory().generateSalt("test-password");
      final String passwordHash = Crypt.crypt("test-password", salt);

      final UserCredential userCredential = mock(UserCredential.class);
      when(userCredential.getName()).thenReturn("/foo");
      when(userCredential.getUuid()).thenReturn(uuid);
      when(userCredential.getCredentialType()).thenReturn("user");
      when(userCredential.getPassword()).thenReturn("test-password");
      when(userCredential.getUsername()).thenReturn("test-username");
      when(userCredential.getSalt()).thenReturn(salt);

      UserView actual = (UserView) UserView.fromEntity(userCredential);

      assertThat(json(actual), equalTo("{"
          + "\"type\":\"user\","
          + "\"version_created_at\":null,"
          + "\"id\":\"" + uuid.toString() + "\","
          + "\"name\":\"/foo\","
          + "\"value\":{"
          + "\"username\":\"test-username\","
          + "\"password\":\"test-password\","
          + "\"password_hash\":\"" + passwordHash + "\""
          + "}}"));
    });
  }
}
