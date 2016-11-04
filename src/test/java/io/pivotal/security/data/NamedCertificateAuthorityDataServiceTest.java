package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.repository.NamedCertificateAuthorityRepository;
import io.pivotal.security.service.EncryptionService;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class NamedCertificateAuthorityDataServiceTest {
  @Autowired
  NamedCertificateAuthorityDataService subject;

  @Autowired
  JdbcTemplate jdbcTemplate;

  @Autowired
  EncryptionService encryptionService;

  @Autowired
  NamedCertificateAuthorityRepository namedCertificateAuthorityRepository;

  private Instant frozenTime = Instant.ofEpochSecond(1400000000L);
  private Consumer<Long> fakeTimeSetter;

  {
    wireAndUnwire(this);
    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      fakeTimeSetter.accept(frozenTime.toEpochMilli());
    });

    afterEach(() -> {
      jdbcTemplate.execute("delete from named_certificate_authority");
    });

    describe("#save", () -> {
      it("should create the entity in the database", () -> {
        NamedCertificateAuthority certificateAuthority = createCertificateAuthority("test-ca", "fake-certificate", "fake-encrypted-value");
        certificateAuthority = subject.save(certificateAuthority);

        assertNotNull(certificateAuthority);

        List<NamedCertificateAuthority> certificateAuthorities = jdbcTemplate.query("select * from named_certificate_authority", (rs, rowCount) -> {
          NamedCertificateAuthority ca = new NamedCertificateAuthority();

          ca.setCertificate(rs.getString("certificate"));
          ca.setEncryptedValue(rs.getBytes("encrypted_value"));
          ca.setName(rs.getString("name"));
          ca.setNonce(rs.getBytes("nonce"));
          ca.setType(rs.getString("type"));
          ca.setUpdatedAt(Instant.ofEpochSecond(rs.getLong("updated_at")));

          return ca;
        });

        assertThat(certificateAuthorities.size(), equalTo(1));

        NamedCertificateAuthority actual = certificateAuthorities.get(0);
        NamedCertificateAuthority expected = certificateAuthority;

        assertThat(actual.getCertificate(), equalTo(expected.getCertificate()));
        assertThat(actual.getEncryptedValue(), equalTo(expected.getEncryptedValue()));
        assertThat(actual.getName(), equalTo(expected.getName()));
        assertThat(actual.getNonce(), equalTo(expected.getNonce()));
        assertThat(actual.getType(), equalTo(expected.getType()));
        assertThat(actual.getUpdatedAt(), equalTo(expected.getUpdatedAt()));
        assertThat(actual.getUpdatedAt(), equalTo(frozenTime));

        // The Java UUID class doesn't let us convert to UUID type 4... so
        // we must rely on Hibernate to do that for us.
        certificateAuthorities = namedCertificateAuthorityRepository.findAll();
        UUID actualUuid = certificateAuthorities.get(0).getUuid();
        assertNotNull(actualUuid);
        assertThat(actualUuid, equalTo(expected.getUuid()));
      });

      it("can store a CA with a certificate of length 7000", () -> {
        final StringBuilder stringBuilder = new StringBuilder(7000);
        Stream.generate(() -> "a").limit(stringBuilder.capacity()).forEach(stringBuilder::append);
        String certificate = stringBuilder.toString();
        NamedCertificateAuthority certificateAuthority = createCertificateAuthority("test-ca", certificate, "fake-encrypted-value");

        certificateAuthority = subject.save(certificateAuthority);

        List<NamedCertificateAuthority> certificateAuthorities = jdbcTemplate.query("select * from named_certificate_authority", (rs, rowCount) -> {
          NamedCertificateAuthority ca = new NamedCertificateAuthority();

          ca.setCertificate(rs.getString("certificate"));

          return ca;
        });

        assertThat(certificateAuthorities.size(), equalTo(1));

        assertThat(certificateAuthorities.get(0).getCertificate(), equalTo(certificateAuthority.getCertificate()));
        assertThat(certificateAuthorities.get(0).getCertificate().length(), equalTo(7000));
      });

      it("can store a CA with a private key of length 7000", () -> {
        final StringBuilder stringBuilder = new StringBuilder(7000);
        Stream.generate(() -> "a").limit(stringBuilder.capacity()).forEach(stringBuilder::append);
        String privateKey = stringBuilder.toString();
        NamedCertificateAuthority certificateAuthority = createCertificateAuthority("test-ca", "fake-certificate", privateKey);

        certificateAuthority = subject.save(certificateAuthority);

        List<NamedCertificateAuthority> certificateAuthorities = jdbcTemplate.query("select * from named_certificate_authority", (rs, rowCount) -> {
          NamedCertificateAuthority ca = new NamedCertificateAuthority();

          ca.setNonce(rs.getBytes("nonce"));
          ca.setEncryptedValue(rs.getBytes("encrypted_value"));

          return ca;
        });

        assertThat(certificateAuthorities.size(), equalTo(1));

        NamedCertificateAuthority actual = certificateAuthorities.get(0);
        assertThat(actual.getNonce(), equalTo(certificateAuthority.getNonce()));
        assertThat(actual.getEncryptedValue(), equalTo(certificateAuthority.getEncryptedValue()));
        assertThat(actual.getPrivateKey(), equalTo(certificateAuthority.getPrivateKey()));
        assertThat(actual.getPrivateKey().length(), equalTo(7000));
      });

      describe("when the entity already exists", () -> {
        it("should save the updated entity", () -> {
          NamedCertificateAuthority certificateAuthority = subject.save(createCertificateAuthority("test-name", "original-certificate", "test-private-key"));
          String newCertificateValue = "new-certificate";
          certificateAuthority.setCertificate(newCertificateValue);
          certificateAuthority = subject.save(certificateAuthority);

          List<NamedCertificateAuthority> certificateAuthorities = namedCertificateAuthorityRepository.findAll();

          assertThat(certificateAuthorities.size(), equalTo(1));
          NamedCertificateAuthority actual = certificateAuthorities.get(0);

          assertThat(actual.getUuid(), equalTo(certificateAuthority.getUuid()));
          assertThat(actual.getCertificate(), equalTo(newCertificateValue));
        });
      });
    });

    describe("#find", () -> {
      beforeEach(() -> {
        subject.save(createCertificateAuthority("test-ca", "fake-certificate", "fake-encrypted-value"));
        subject.save(createCertificateAuthority("TEST", "fake-certificate", "fake-encrypted-value"));
        subject.save(createCertificateAuthority("FOO", "fake-certificate", "fake-encrypted-value"));
      });

      describe("when there is no entity with the name", () -> {
        it("should return null", () -> {
          NamedCertificateAuthority certificateAuthority = subject.find("this-entity-does-not-exist");

          assertNull(certificateAuthority);
        });
      });

      describe("when given a name in the same case as the entity's name", () -> {
        it("should retrieve the entity from the database", () -> {
          NamedCertificateAuthority certificateAuthority = subject.find("test-ca");

          assertNotNull(certificateAuthority);
          assertThat(certificateAuthority.getName(), equalTo("test-ca"));
        });
      });

      describe("when given a name with a different case than the entity's name", () -> {
        it("should still retrieve the entity from the database", () -> {
          NamedCertificateAuthority certificateAuthority = subject.find("TEST-CA");

          assertNotNull(certificateAuthority);
          assertThat(certificateAuthority.getName(), equalTo("test-ca"));
        });
      });
    });

    describe("#findOneByUuid", () -> {
      it("should be able to find a CA by uuid", () -> {
        NamedCertificateAuthority certificateAuthority = createCertificateAuthority("my-ca", "my-cert", "my-priv");
        NamedCertificateAuthority savedSecret = subject.save(certificateAuthority);

        assertNotNull(savedSecret.getUuid());
        NamedCertificateAuthority oneByUuid = subject.findOneByUuid(savedSecret.getUuid().toString());
        assertThat(oneByUuid.getName(), equalTo("my-ca"));
        assertThat(oneByUuid.getCertificate(), equalTo("my-cert"));
        assertThat(oneByUuid.getPrivateKey(), equalTo("my-priv"));
      });
    });
  }

  NamedCertificateAuthority createCertificateAuthority(String name, String certificate, String privateKey) {
    NamedCertificateAuthority certificateAuthority = new NamedCertificateAuthority(name);

    certificateAuthority.setCertificate(certificate);
    certificateAuthority.setPrivateKey(privateKey);
    certificateAuthority.setType("test-ca-type");

    return certificateAuthority;
  }
}
