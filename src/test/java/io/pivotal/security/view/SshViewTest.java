package io.pivotal.security.view;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.helper.TestConstants;
import io.pivotal.security.service.Encryption;
import org.json.JSONObject;
import org.junit.runner.RunWith;
import org.springframework.test.util.JsonExpectationsHelper;

import java.time.Instant;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.json;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class SshViewTest {

  private static final JsonExpectationsHelper jsonExpectationsHelper = new JsonExpectationsHelper();

  private NamedSshSecret entity;

  private String secretName;

  private UUID uuid;

  private Encryptor encryptor;

  {
    beforeEach(() -> {
      secretName = "/foo";
      uuid = UUID.randomUUID();
      encryptor = mock(Encryptor.class);
      when(encryptor.encrypt(TestConstants.PRIVATE_KEY_4096)).thenReturn(new Encryption(UUID.randomUUID(), "encrypted".getBytes(), "nonce".getBytes()));
      when(encryptor.decrypt(any(UUID.class), any(byte[].class), any(byte[].class))).thenReturn(TestConstants.PRIVATE_KEY_4096);
      entity = new NamedSshSecret(secretName)
          .setEncryptor(encryptor)
          .setPublicKey(TestConstants.SSH_PUBLIC_KEY_4096_WITH_COMMENT)
          .setPrivateKey(TestConstants.PRIVATE_KEY_4096);
      entity.setUuid(uuid);
    });

    it("creates a view from entity", () -> {
      final SecretView subject = SshView.fromEntity(entity);

      JSONObject obj = new JSONObject();
      obj.put("public_key", TestConstants.SSH_PUBLIC_KEY_4096_WITH_COMMENT);
      obj.put("private_key", TestConstants.PRIVATE_KEY_4096);
      obj.put("public_key_fingerprint", "UmqxK9UJJR4Jrcw0DcwqJlCgkeQoKp8a+HY+0p0nOgc");
      String expected = "{" +
          "\"id\":\"" + uuid.toString() + "\"," +
          "\"type\":\"ssh\"," +
          "\"name\":\"/foo\"," +
          "\"version_created_at\":null," +
          "\"value\":" + obj.toString() +
        "}";

      jsonExpectationsHelper.assertJsonEqual(expected, json(subject), true);
    });

    it("sets updated-at time on generated view", () -> {
      Instant now = Instant.now();
      entity.setVersionCreatedAt(now);
      final SshView subject = (SshView) SshView.fromEntity(entity);
      assertThat(subject.getVersionCreatedAt(), equalTo(now));
    });

    it("sets uuid on generated view", () -> {
      SshView subject = (SshView) SshView.fromEntity(entity);
      assertThat(subject.getUuid(), equalTo(uuid.toString()));
    });
  }
}
