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

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.fit;
import static com.greghaskins.spectrum.Spectrum.it;
import static com.greghaskins.spectrum.Spectrum.xdescribe;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
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
        certificateAuthority = subject.saveWithEncryption(certificateAuthority);

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

        certificateAuthority = subject.saveWithEncryption(certificateAuthority);

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

        certificateAuthority = subject.saveWithEncryption(certificateAuthority);

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
        subject.saveWithEncryption(certificateAuthority);

        verify(secretEncryptionHelper).refreshEncryptedValue(eq(certificateAuthority), eq("fake-private-key"));
      });

      describe("when the entity already exists", () -> {
        it("should save the updated entity", () -> {
          NamedCertificateAuthority certificateAuthority = subject.saveWithEncryption(createCertificateAuthority("test-name", "original-certificate", "fake-private-key"));
          String newCertificateValue = "new-certificate";
          certificateAuthority.setCertificate(newCertificateValue);
          certificateAuthority = subject.saveWithEncryption(certificateAuthority);

          List<NamedCertificateAuthority> certificateAuthorities = namedCertificateAuthorityRepository.findAll();

          assertThat(certificateAuthorities.size(), equalTo(1));
          NamedCertificateAuthority actual = certificateAuthorities.get(0);

          assertThat(actual.getUuid(), equalTo(certificateAuthority.getUuid()));
          assertThat(actual.getCertificate(), equalTo(newCertificateValue));
        });
      });
    });

    describe("#findMostRecentByNameWithEncryption", () -> {
      beforeEach(() -> {
        subject.saveWithEncryption(createCertificateAuthority("test-ca", "fake-certificate", "fake-private-key"));
        subject.saveWithEncryption(createCertificateAuthority("TEST", "fake-certificate", "fake-private-key"));
        subject.saveWithEncryption(createCertificateAuthority("FOO", "fake-certificate", "fake-private-key"));
      });

      describe("when there is no entity with the name", () -> {
        it("should return null", () -> {
          NamedCertificateAuthority certificateAuthority = subject.findMostRecentByNameWithDecryption("this-entity-does-not-exist");
          assertNull(certificateAuthority);
        });
      });

      describe("when given a name in the same case as the entity's name", () -> {
        it("should retrieve the entity from the database", () -> {
          NamedCertificateAuthority certificateAuthority = subject.findMostRecentByNameWithDecryption("test-ca");
          assertNotNull(certificateAuthority);
          assertThat(certificateAuthority.getName(), equalTo("test-ca"));
        });

        it("should decrypt private key of the returned CA", () -> {
          NamedCertificateAuthority certificateAuthority = subject.findMostRecentByNameWithDecryption("test-ca");
          verify(secretEncryptionHelper, times(1)).retrieveClearTextValue(eq(certificateAuthority));
        });
      });

      describe("when given a name with a different case than the entity's name", () -> {
        it("should still retrieve the entity from the database", () -> {
          NamedCertificateAuthority certificateAuthority = subject.findMostRecentByNameWithDecryption("TEST-CA");

          assertNotNull(certificateAuthority);
          assertThat(certificateAuthority.getName(), equalTo("test-ca"));
        });
      });
    });

    xdescribe("#findAllByName", () -> {
      beforeEach(() -> {
        subject.saveWithEncryption(createCertificateAuthority("ca-with-versions", "fake-certificate", "fake-private-key"));
        subject.saveWithEncryption(createCertificateAuthority("ca-with-versions", "fake-certificate2", "fake-private-key"));
        subject.saveWithEncryption(createCertificateAuthority("ca-with-versions", "fake-certificate3", "fake-private-key"));
        subject.saveWithEncryption(createCertificateAuthority("test-ca", "fake-certificate", "fake-private-key"));
      });

      it("should find all versions given a name", () -> {
        List<NamedCertificateAuthority> cas = subject.findAllByName("ca-with-versions");
        assertThat(cas.size(), equalTo(3));
      });
    });

    describe("#findOneByUuidWithDecryption", () -> {
      beforeEach(() -> {
        NamedCertificateAuthority certificateAuthority = createCertificateAuthority("my-ca", "my-cert", "my-priv");
        savedSecret = subject.saveWithEncryption(certificateAuthority);
        assertNotNull(savedSecret.getUuid());
      });

      it("should return null for non-existent uuid", () -> {
        NamedCertificateAuthority certificateAuthority = subject.findOneByUuidWithDecryption(UUID.randomUUID().toString());
        assertNull(certificateAuthority);
      });

      it("should be able to find a CA by uuid", () -> {
        NamedCertificateAuthority oneByUuid = subject.findOneByUuidWithDecryption(savedSecret.getUuid().toString());
        assertThat(oneByUuid.getName(), equalTo("my-ca"));
        assertThat(oneByUuid.getCertificate(), equalTo("my-cert"));
      });

      it("decrypts private key of the found CA", () -> {
        NamedCertificateAuthority oneByUuid = subject.findOneByUuidWithDecryption(savedSecret.getUuid().toString());
        verify(secretEncryptionHelper, times(1)).retrieveClearTextValue(eq(oneByUuid));
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
