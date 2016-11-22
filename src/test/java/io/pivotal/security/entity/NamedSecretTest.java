package io.pivotal.security.entity;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.function.Consumer;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class NamedSecretTest {
  @Autowired
  SecretDataService secretDataService;

  private Consumer<Long> fakeTimeSetter;
  private NamedCertificateSecret subject;
  private String secretName;

  private final Instant FROZEN_TIME = Instant.ofEpochMilli(1400000000123L);

  {
    wireAndUnwire(this, true);

    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      fakeTimeSetter.accept(FROZEN_TIME.toEpochMilli());
      secretName = "foo";
      subject = new NamedCertificateSecret(secretName)
          .setCa("ca")
          .setCertificate("pub")
          .setPrivateKey("priv");
    });

    it("returns date created", () -> {
      subject = (NamedCertificateSecret) secretDataService.save(subject);
      assertThat(secretDataService.findMostRecent(secretName).getUpdatedAt(), equalTo(FROZEN_TIME));
    });

    it("returns date updated", () -> {
      long updatedTime = FROZEN_TIME.toEpochMilli() + 1000;
      subject = (NamedCertificateSecret) secretDataService.save(subject);
      fakeTimeSetter.accept(updatedTime);
      subject.setPrivateKey("new-priv");  // Change object so that Hibernate will update the database
      subject = (NamedCertificateSecret) secretDataService.save(subject);
      assertThat(secretDataService.findMostRecent(secretName).getUpdatedAt().toEpochMilli(), equalTo(updatedTime));
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
