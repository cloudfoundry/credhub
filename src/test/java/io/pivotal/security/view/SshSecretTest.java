package io.pivotal.security.view;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.NamedSshSecret;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.JsonExpectationsHelper;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.json;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

import java.time.Instant;
import java.util.UUID;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test", "FakeEncryptionService"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SshSecretTest {

  private static final JsonExpectationsHelper jsonExpectationsHelper = new JsonExpectationsHelper();

  @Autowired
  SecretDataService secretDataService;

  @Autowired
  ObjectMapper serializingObjectMapper;

  private NamedSshSecret entity;

  private String secretName;

  private UUID uuid;

  {
    wireAndUnwire(this, false);

    beforeEach(() -> {
      secretName = "foo";
      uuid = UUID.randomUUID();
      entity = new NamedSshSecret(secretName)
          .setPublicKey("my-public-key")
          .setPrivateKey("my-private-key");
      entity.setUuid(uuid);
    });

    it("creates a view from entity", () -> {
      final Secret subject = SshSecret.fromEntity(entity);
      jsonExpectationsHelper.assertJsonEqual("{" +
          "\"id\":\"" + uuid.toString() + "\"," +
          "\"type\":\"ssh\"," +
          "\"name\":\"foo\"," +
          "\"updated_at\":null," +
          "\"value\":{" +
            "\"public_key\":\"my-public-key\"," +
            "\"private_key\":\"my-private-key\"" +
          "}" +
        "}", json(subject), true);
    });

    it("sets updated-at time on generated view", () -> {
      Instant now = Instant.now();
      entity.setUpdatedAt(now);
      final SshSecret subject = (SshSecret) SshSecret.fromEntity(entity);
      assertThat(subject.getUpdatedAt(), equalTo(now));
    });

    it("sets uuid on generated view", () -> {
      entity = (NamedSshSecret) secretDataService.save(entity);
      SshSecret subject = (SshSecret) SshSecret.fromEntity(entity);
      assertThat(subject.getUuid(), notNullValue());
    });
  }
}
