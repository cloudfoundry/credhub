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

import java.util.function.Consumer;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class NamedSecretTest {
  @Autowired
  SecretDataService secretDataService;

  private Consumer<Long> fakeTimeSetter;
  private NamedCertificateSecret secret;
  private String secretName;

  {
    wireAndUnwire(this);
    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      fakeTimeSetter.accept(345345L);
      secretName = "foo";
      secret = new NamedCertificateSecret(secretName)
          .setCa("ca")
          .setCertificate("pub")
          .setPrivateKey("priv");
    });

    it("returns date created", () -> {
      secret = (NamedCertificateSecret) secretDataService.save(secret);
      assertThat(secretDataService.findMostRecent(secretName).getUpdatedAt().toEpochMilli(), equalTo(345000L));
    });

    it("returns date updated", () -> {
      secret = (NamedCertificateSecret) secretDataService.save(secret);
      fakeTimeSetter.accept(444444L);
      secret.setPrivateKey("new-priv");  // Change object so that Hibernate will update the database
      secret = (NamedCertificateSecret) secretDataService.save(secret);
      assertThat(secretDataService.findMostRecent(secretName).getUpdatedAt().toEpochMilli(), equalTo(444000L));
    });
  }
}
