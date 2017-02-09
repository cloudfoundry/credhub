package io.pivotal.security.domain;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsNull.notNullValue;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class NamedCertificateSecretTest {
  @Autowired
  JdbcTemplate jdbcTemplate;

  private NamedCertificateSecret subject;

  {
    wireAndUnwire(this, false);

    beforeEach(() -> {
      subject = new NamedCertificateSecret("Foo")
          .setCa("my-ca")
          .setCertificate("my-cert")
          .setPrivateKey("my-priv");
    });

    it("returns type certificate", () -> {
      assertThat(subject.getSecretType(), equalTo("certificate"));
    });

    it("sets the nonce and the encrypted private key", () -> {
      subject.setPrivateKey("my-priv");
      assertThat(subject.getEncryptedValue(), notNullValue());
      assertThat(subject.getNonce(), notNullValue());
    });

    it("can decrypt the private key", () -> {
      subject.setPrivateKey("my-priv");
      assertThat(subject.getPrivateKey(), equalTo("my-priv"));
    });

    describe("#copyInto", () -> {
      it("should copy the correct values", () -> {
        Instant frozenTime = Instant.ofEpochSecond(1400000000L);
        UUID uuid = UUID.randomUUID();
        UUID encryptionKeyUuid = UUID.randomUUID();

        subject = new NamedCertificateSecret("name");
        subject.setCa("fake-ca");
        subject.setCertificate("fake-certificate");
        subject.setEncryptedValue("fake-private-key".getBytes());
        subject.setNonce("fake-nonce".getBytes());
        subject.setCaName("ca-name");
        subject.setUuid(uuid);
        subject.setVersionCreatedAt(frozenTime);
        subject.setEncryptionKeyUuid(encryptionKeyUuid);

        NamedCertificateSecret copy = new NamedCertificateSecret();
        subject.copyInto(copy);

        assertThat(copy.getName(), equalTo("name"));
        assertThat(copy.getCaName(), equalTo("ca-name"));
        assertThat(copy.getCa(), equalTo("fake-ca"));
        assertThat(copy.getEncryptedValue(), equalTo("fake-private-key".getBytes()));
        assertThat(copy.getNonce(), equalTo("fake-nonce".getBytes()));
        assertThat(copy.getEncryptionKeyUuid(), equalTo(encryptionKeyUuid));

        assertThat(copy.getUuid(), not(equalTo(uuid)));
        assertThat(copy.getVersionCreatedAt(), not(equalTo(frozenTime)));
      });
    });
  }
}
