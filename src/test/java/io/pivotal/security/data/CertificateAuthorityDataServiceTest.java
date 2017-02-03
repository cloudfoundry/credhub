package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.helper.EncryptionCanaryHelper;
import io.pivotal.security.repository.CertificateAuthorityRepository;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class CertificateAuthorityDataServiceTest {
  @Autowired
  JdbcTemplate jdbcTemplate;

  @Autowired
  CertificateAuthorityRepository certificateAuthorityRepository;

  @SpyBean
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @Autowired
  EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;

  private Instant frozenTime = Instant.ofEpochMilli(1400000000123L);
  private Consumer<Long> fakeTimeSetter;

  private CertificateAuthorityDataService subject;
  private NamedCertificateAuthority savedSecret;

  private UUID activeCanaryUuid;

  {
    wireAndUnwire(this, false);

    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      jdbcTemplate.execute("delete from named_certificate_authority");
      jdbcTemplate.execute("delete from encryption_key_canary");

      subject = new CertificateAuthorityDataService(certificateAuthorityRepository, encryptionKeyCanaryMapper);

      fakeTimeSetter.accept(frozenTime.toEpochMilli());

      activeCanaryUuid = EncryptionCanaryHelper.addCanary(encryptionKeyCanaryDataService).getUuid();

      when(encryptionKeyCanaryMapper.getActiveUuid()).thenReturn(activeCanaryUuid);
    });

    afterEach(() -> {
      jdbcTemplate.execute("delete from named_certificate_authority");
      jdbcTemplate.execute("delete from encryption_key_canary");
    });

    describe("#save", () -> {
      it("should create the entity in the database", () -> {
        NamedCertificateAuthority certificateAuthority = createCertificateAuthority("test-ca", "fake-certificate");
        certificateAuthority = subject.save(certificateAuthority);

        assertNotNull(certificateAuthority);

        List<NamedCertificateAuthority> certificateAuthorities = jdbcTemplate.query("select * from named_certificate_authority", (rs, rowCount) -> {
          NamedCertificateAuthority ca = new NamedCertificateAuthority();

          ca.setEncryptionKeyUuid(activeCanaryUuid);
          ca.setCertificate(rs.getString("certificate"));
          ca.setEncryptedValue(rs.getBytes("encrypted_value"));
          ca.setName(rs.getString("name"));
          ca.setNonce(rs.getBytes("nonce"));
          ca.setType(rs.getString("type"));
          ca.setVersionCreatedAt(Instant.ofEpochMilli(rs.getLong("version_created_at")));

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
        assertThat(actual.getVersionCreatedAt(), equalTo(expected.getVersionCreatedAt()));
        assertThat(actual.getVersionCreatedAt(), equalTo(frozenTime));

        // The Java UUID class doesn't let us convert to UUID type 4... so
        // we must rely on Hibernate to do that for us.
        certificateAuthorities = certificateAuthorityRepository.findAll();
        UUID actualUuid = certificateAuthorities.get(0).getUuid();
        assertNotNull(actualUuid);
        assertThat(actualUuid, equalTo(expected.getUuid()));
      });

      it("can store a CA with a certificate of length 7000", () -> {
        String certificate = buildLargeString(7000);
        NamedCertificateAuthority certificateAuthority = createCertificateAuthority("test-ca", certificate);

        certificateAuthority = subject.save(certificateAuthority);

        List<NamedCertificateAuthority> certificateAuthorities = jdbcTemplate.query("select * from named_certificate_authority", (rs, rowCount) -> {
          NamedCertificateAuthority ca = new NamedCertificateAuthority();
          ca.setEncryptionKeyUuid(activeCanaryUuid);

          ca.setCertificate(rs.getString("certificate"));

          return ca;
        });

        assertThat(certificateAuthorities.size(), equalTo(1));

        assertThat(certificateAuthorities.get(0).getCertificate(), equalTo(certificateAuthority.getCertificate()));
        assertThat(certificateAuthorities.get(0).getCertificate().length(), equalTo(7000));
      });

      it("can store a CA with a private key of length 7000", () -> {
        NamedCertificateAuthority certificateAuthority = createCertificateAuthority("test-ca", "fake-certificate");
        String largeString = buildLargeString(7000);
        certificateAuthority.setEncryptedValue(largeString.getBytes());

        certificateAuthority = subject.save(certificateAuthority);

        List<NamedCertificateAuthority> certificateAuthorities = jdbcTemplate.query("select * from named_certificate_authority", (rs, rowCount) -> {
          NamedCertificateAuthority ca = new NamedCertificateAuthority();

          ca.setEncryptionKeyUuid(activeCanaryUuid);
          ca.setNonce(rs.getBytes("nonce"));
          ca.setEncryptedValue(rs.getBytes("encrypted_value"));

          return ca;
        });

        assertThat(certificateAuthorities.size(), equalTo(1));

        NamedCertificateAuthority actual = certificateAuthorities.get(0);
        assertThat(actual.getNonce(), equalTo(certificateAuthority.getNonce()));
        assertThat(new String(actual.getEncryptedValue()).length(), equalTo(7000));
      });

      describe("when the entity already exists", () -> {
        it("should save the updated entity", () -> {
          NamedCertificateAuthority certificateAuthority = subject.save(createCertificateAuthority("test-name", "original-certificate"));
          String newCertificateValue = "new-certificate";
          certificateAuthority.setCertificate(newCertificateValue);
          certificateAuthority = subject.save(certificateAuthority);

          List<NamedCertificateAuthority> certificateAuthorities = certificateAuthorityRepository.findAll();

          assertThat(certificateAuthorities.size(), equalTo(1));
          NamedCertificateAuthority actual = certificateAuthorities.get(0);

          assertThat(actual.getUuid(), equalTo(certificateAuthority.getUuid()));
          assertThat(actual.getCertificate(), equalTo(newCertificateValue));
        });
      });
    });

    describe("#findMostRecent", () -> {
      beforeEach(() -> {
        subject.save(createCertificateAuthority("test-ca", "fake-certificate"));
        subject.save(createCertificateAuthority("TEST", "fake-certificate"));
        subject.save(createCertificateAuthority("FOO", "fake-certificate"));
      });

      describe("when there is no entity with the name", () -> {
        it("should return null", () -> {
          NamedCertificateAuthority mostRecentCA = subject.findMostRecent("this-entity-does-not-exist");

          assertNull(mostRecentCA);
        });
      });

      describe("when given a name in the same case as the entity's name", () -> {
        it("should retrieve the entity from the database", () -> {
          NamedCertificateAuthority certificateAuthority = subject.findMostRecent("test-ca");
          assertNotNull(certificateAuthority);
          assertThat(certificateAuthority.getName(), equalTo("test-ca"));
        });
      });

      describe("when given a name with a different case than the entity's name", () -> {
        it("should still retrieve the entity from the database", () -> {
          NamedCertificateAuthority certificateAuthority = subject.findMostRecent("TEST-CA");

          assertNotNull(certificateAuthority);
          assertThat(certificateAuthority.getName(), equalTo("test-ca"));
        });
      });

      it("finds most recent based on version_created_at date, not updated_at", () -> {
        NamedCertificateAuthority firstCertificate = new NamedCertificateAuthority("my-certificate");
        firstCertificate.setCertificate("first-certificate");

        NamedCertificateAuthority secondCertificate = new NamedCertificateAuthority("my-certificate");
        secondCertificate.setCertificate("second-certificate");

        firstCertificate = subject.save(firstCertificate);
        fakeTimeSetter.accept(1400000000124L);
        secondCertificate = subject.save(secondCertificate);

        NamedCertificateAuthority mostRecent = subject.findMostRecent("my-certificate");
        assertThat(mostRecent.getCertificate(), equalTo("second-certificate"));

        firstCertificate.setCertificate("updated-first-certificate");
        fakeTimeSetter.accept(1400000000125L);
        subject.save(firstCertificate);

        mostRecent = subject.findMostRecent("my-certificate");
        assertThat(mostRecent.getCertificate(), equalTo("second-certificate"));
      });
    });

    describe("#findAllByName", () -> {
      it("finds all versions given a name in reverse chronological order", () -> {
        fakeTimeSetter.accept(3000000000L);
        subject.save(createCertificateAuthority("CA/with/versions", "fake-certificate1"));
        fakeTimeSetter.accept(1000000000L);
        subject.save(createCertificateAuthority("ca/WITH/versions", "fake-certificate2"));
        fakeTimeSetter.accept(2000000000L);
        subject.save(createCertificateAuthority("ca/with/VERSIONS", "fake-certificate3"));
        subject.save(createCertificateAuthority("test-ca", "fake-certificate"));

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

    describe("#findByUuid", () -> {
      it("should be able to find a CA by uuid", () -> {
        NamedCertificateAuthority certificateAuthority = createCertificateAuthority("my-ca", "my-cert");
        savedSecret = subject.save(certificateAuthority);
        assertNotNull(savedSecret.getUuid());
        NamedCertificateAuthority oneByUuid = subject.findByUuid(savedSecret.getUuid().toString());
        assertThat(oneByUuid.getName(), equalTo("my-ca"));
        assertThat(oneByUuid.getCertificate(), equalTo("my-cert"));
      });

      it("returns null when no CA is found", () -> {
        NamedCertificateAuthority foundNamedCertificateAuthority = subject.findByUuid(UUID.randomUUID().toString());
        assertNull(foundNamedCertificateAuthority);
      });
    });
  }

  private String buildLargeString(int stringLength) {
    final StringBuilder stringBuilder = new StringBuilder(stringLength);
    Stream.generate(() -> "a").limit(stringBuilder.capacity()).forEach(stringBuilder::append);
    return stringBuilder.toString();
  }

  NamedCertificateAuthority createCertificateAuthority(String name, String certificate, UUID canaryUuid) {
    NamedCertificateAuthority certificateAuthority = new NamedCertificateAuthority(name);
    certificateAuthority.setEncryptionKeyUuid(canaryUuid);

    certificateAuthority
        .setType("test-ca-type")
        .setCertificate(certificate);

    return certificateAuthority;
  }

  NamedCertificateAuthority createCertificateAuthority(String name, String certificate) {
    return createCertificateAuthority(name, certificate, activeCanaryUuid);
  }
}
