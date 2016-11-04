package io.pivotal.security.entity;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.data.SecretDataService;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;
import org.springframework.util.StringUtils;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.cleanUpAfterTests;
import static io.pivotal.security.helper.SpectrumHelper.cleanUpBeforeTests;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.function.Consumer;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class NamedSecretTest {
  @Autowired
  SecretDataService secretDataService;

  private Consumer<Long> fakeTimeSetter;
  private NamedCertificateSecret subject;
  private String secretName;

  {
    wireAndUnwire(this);
    cleanUpBeforeTests(this);
    cleanUpAfterTests(this);

    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      fakeTimeSetter.accept(345345L);
      secretName = "foo";
      subject = new NamedCertificateSecret(secretName)
          .setCa("ca")
          .setCertificate("pub")
          .setPrivateKey("priv");
    });

    it("returns date created", () -> {
      subject = (NamedCertificateSecret) secretDataService.save(subject);
      assertThat(secretDataService.findMostRecent(secretName).getUpdatedAt().toEpochMilli(), equalTo(345000L));
    });

    it("returns date updated", () -> {
      subject = (NamedCertificateSecret) secretDataService.save(subject);
      fakeTimeSetter.accept(444444L);
      subject.setPrivateKey("new-priv");  // Change object so that Hibernate will update the database
      subject = (NamedCertificateSecret) secretDataService.save(subject);
      assertThat(secretDataService.findMostRecent(secretName).getUpdatedAt().toEpochMilli(), equalTo(444000L));
    });

    it("should have a consistent UUID", () -> {
      subject = (NamedCertificateSecret) secretDataService.save(this.subject);
      String originalUuid = subject.getUuid().toString();

      assertThat(StringUtils.isEmpty(originalUuid), equalTo(false));

      subject.setCertificate("fake-new-certificate");
      subject = (NamedCertificateSecret) secretDataService.save(subject);

      assertThat(subject.getUuid().toString(), equalTo(originalUuid));
    });
  }
}
