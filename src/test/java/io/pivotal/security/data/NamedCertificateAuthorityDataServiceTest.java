package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.entity.SecretEncryptionHelper;
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
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class NamedCertificateAuthorityDataServiceTest {
  @Autowired
  JdbcTemplate jdbcTemplate;

  @Autowired
  EncryptionService encryptionService;

  @Autowired
  NamedCertificateAuthorityRepository namedCertificateAuthorityRepository;

  private Instant frozenTime = Instant.ofEpochMilli(1400000000123L);
  private Consumer<Long> fakeTimeSetter;

  private NamedCertificateAuthorityDataService subject;
  private SecretEncryptionHelper secretEncryptionHelper;
  private NamedCertificateAuthority savedSecret;

  {
    wireAndUnwire(this);

    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      secretEncryptionHelper = mock(SecretEncryptionHelper.class);
      subject = new NamedCertificateAuthorityDataService(namedCertificateAuthorityRepository, secretEncryptionHelper);

      fakeTimeSetter.accept(frozenTime.toEpochMilli());
    });

    afterEach(() -> {
      jdbcTemplate.execute("delete from named_certificate_authority");
    });

    describe("#saveWithEncryption", () -> {
      it("should create the entity in the database", () -> {
        NamedCertificateAuthority certificateAuthority = createCertificateAuthority("test-ca", "fake-certificate", "fake-private-key");
        certificateAuthority = subject.save(certificateAuthority);

        assertNotNull(certificateAuthority);

        List<NamedCertificateAuthority> certificateAuthorities = jdbcTemplate.query("select * from named_certificate_authority", (rs, rowCount) -> {
          NamedCertificateAuthority ca = new NamedCertificateAuthority();

          ca.setCertificate(rs.getString("certificate"));
          ca.setEncryptedValue(rs.getBytes("encrypted_value"));
          ca.setName(rs.getString("name"));
          ca.setNonce(rs.getBytes("nonce"));
          ca.setType(rs.getString("type"));
          ca.setUpdatedAt(Instant.ofEpochMilli(rs.getLong("updated_at")));

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
        String certificate = buildLargeString(7000);
        NamedCertificateAuthority certificateAuthority = createCertificateAuthority("test-ca", certificate, "test-private-key");

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
        NamedCertificateAuthority certificateAuthority = createCertificateAuthority("test-ca", "fake-certificate", "fake-private-key");
        String largeString = buildLargeString(7000);
        certificateAuthority.setEncryptedValue(largeString.getBytes());

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
        assertThat(new String(actual.getEncryptedValue()).length(), equalTo(7000));
      });

      it("should encrypt private key", () -> {
        NamedCertificateAuthority certificateAuthority = createCertificateAuthority("test-ca", "fake-certificate", "fake-private-key");
        subject.save(certificateAuthority);

        verify(secretEncryptionHelper).refreshEncryptedValue(eq(certificateAuthority), eq("fake-private-key"));
      });

      describe("when the entity already exists", () -> {
        it("should save the updated entity", () -> {
          NamedCertificateAuthority certificateAuthority = subject.save(createCertificateAuthority("test-name", "original-certificate", "fake-private-key"));
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

    describe("#findMostRecentAsList", () -> {
      beforeEach(() -> {
        subject.save(createCertificateAuthority("test-ca", "fake-certificate", "fake-private-key"));
        subject.save(createCertificateAuthority("TEST", "fake-certificate", "fake-private-key"));
        subject.save(createCertificateAuthority("FOO", "fake-certificate", "fake-private-key"));
      });

      describe("when there is no entity with the name", () -> {
        it("should return empty list", () -> {
          List<NamedCertificateAuthority> mostRecentCAAsList = subject.findMostRecentAsList("this-entity-does-not-exist");

          assertTrue(mostRecentCAAsList.isEmpty());
        });
      });

      describe("when given a name in the same case as the entity's name", () -> {
        it("should retrieve the entity from the database", () -> {
          NamedCertificateAuthority certificateAuthority = subject.findMostRecentAsList("test-ca").get(0);
          assertNotNull(certificateAuthority);
          assertThat(certificateAuthority.getName(), equalTo("test-ca"));
        });

        it("should decrypt private key of the returned CA", () -> {
          NamedCertificateAuthority certificateAuthority = subject.findMostRecentAsList("test-ca").get(0);
          verify(secretEncryptionHelper, times(1)).retrieveClearTextValue(eq(certificateAuthority));
        });
      });

      describe("when given a name with a different case than the entity's name", () -> {
        it("should still retrieve the entity from the database", () -> {
          NamedCertificateAuthority certificateAuthority = subject.findMostRecentAsList("TEST-CA").get(0);

          assertNotNull(certificateAuthority);
          assertThat(certificateAuthority.getName(), equalTo("test-ca"));
        });
      });
    });

    describe("#findAllByName", () -> {
      it("finds all versions given a name in reverse chronological order", () -> {
        fakeTimeSetter.accept(3000000000L);
        subject.save(createCertificateAuthority("CA/with/versions", "fake-certificate1", "fake-private-key"));
        fakeTimeSetter.accept(1000000000L);
        subject.save(createCertificateAuthority("ca/WITH/versions", "fake-certificate2", "fake-private-key"));
        fakeTimeSetter.accept(2000000000L);
        subject.save(createCertificateAuthority("ca/with/VERSIONS", "fake-certificate3", "fake-private-key"));
        subject.save(createCertificateAuthority("test-ca", "fake-certificate", "fake-private-key"));

        List<NamedCertificateAuthority> certificateAuthorities = subject.findAllByName("ca/with/versions");
        assertThat(certificateAuthorities.size(), equalTo(3));
        assertThat(certificateAuthorities.get(0).getCertificate(), equalTo("fake-certificate1"));
        assertThat(certificateAuthorities.get(1).getCertificate(), equalTo("fake-certificate3"));
        assertThat(certificateAuthorities.get(2).getCertificate(), equalTo("fake-certificate2"));
      });

      it("returns empty list when none are found", () -> {
        List<NamedCertificateAuthority> certificateAuthorities = subject.findAllByName("nonexistent-name");
        assertNotNull(certificateAuthorities);
        assertTrue(certificateAuthorities.isEmpty());
      });
    });

    describe("#findByUuidAsList", () -> {
      beforeEach(() -> {
        NamedCertificateAuthority certificateAuthority = createCertificateAuthority("my-ca", "my-cert", "my-priv");
        savedSecret = subject.save(certificateAuthority);
        assertNotNull(savedSecret.getUuid());
      });

      it("should be able to find a CA by uuid", () -> {
        NamedCertificateAuthority oneByUuid = subject.findByUuidAsList(savedSecret.getUuid().toString()).get(0);
        assertThat(oneByUuid.getName(), equalTo("my-ca"));
        assertThat(oneByUuid.getCertificate(), equalTo("my-cert"));
      });

      it("decrypts private key of the found CA", () -> {
        NamedCertificateAuthority oneByUuid = subject.findByUuidAsList(savedSecret.getUuid().toString()).get(0);
        verify(secretEncryptionHelper, times(1)).retrieveClearTextValue(eq(oneByUuid));
      });

      describe("when no CA is found", () -> {
        it("returns an empty list", () -> {
          List<NamedCertificateAuthority> foundNamedCertificateAuthorities = subject.findByUuidAsList(UUID.randomUUID().toString());
          assertNotNull(foundNamedCertificateAuthorities);
          assertTrue(foundNamedCertificateAuthorities.isEmpty());
        });
      });
    });
  }

  private String buildLargeString(int stringLength) {
    final StringBuilder stringBuilder = new StringBuilder(stringLength);
    Stream.generate(() -> "a").limit(stringBuilder.capacity()).forEach(stringBuilder::append);
    return stringBuilder.toString();
  }

  NamedCertificateAuthority createCertificateAuthority(String name, String certificate, String privateKey) {
    NamedCertificateAuthority certificateAuthority = new NamedCertificateAuthority(name);

    certificateAuthority
        .setType("test-ca-type")
        .setCertificate(certificate)
        .setPrivateKey(privateKey);

    return certificateAuthority;
  }
}
