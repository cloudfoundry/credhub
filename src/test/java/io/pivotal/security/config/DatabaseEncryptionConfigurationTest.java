package io.pivotal.security.config;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.entity.NamedStringSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.service.EncryptionService;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import java.util.Collections;
import java.util.Map;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.Matchers.equalToIgnoringCase;
import static org.hamcrest.collection.IsMapContaining.hasEntry;
import static org.junit.Assert.assertThat;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class DatabaseEncryptionConfigurationTest {

  @Autowired
  SecretRepository secretRepository;

  @Autowired
  NamedParameterJdbcTemplate namedParameterJdbcTemplate;

  @Autowired
  EncryptionService encryptionService;

  private String secretName;

  {
    wireAndUnwire(this);

    describe("when a value has been written to the database", () -> {
      beforeEach(() -> {
        secretName = "test";
        NamedStringSecret stringSecret = new NamedValueSecret(secretName, "value1");
        secretRepository.saveAndFlush(stringSecret);
      });

      it("it encrypts the secret value", () -> {
        Map<String, Object> map = namedParameterJdbcTemplate.queryForMap("SELECT s.encrypted_value, n.nonce FROM named_secret s INNER JOIN named_secret n ON s.id = n.id WHERE n.name = '" + secretName + "'", Collections.emptyMap());
        assertThat(map, allOf(
            hasEntry(equalToIgnoringCase("encrypted_value"), not(equalTo("value1"))),
            hasEntry(equalToIgnoringCase("nonce"), notNullValue())
        ));
      });

      it("it decrypts the secret value when the entity is retrieved", () -> {
        NamedStringSecret secret = (NamedStringSecret) secretRepository.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(secretName);
        assertThat(secret.getValue(), equalTo("value1"));
      });
    });
  }
}
