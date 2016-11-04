package io.pivotal.security.util;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertThat;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class UuidGeneratorTest {
  @Autowired
  UuidGenerator subject;

  {
    wireAndUnwire(this);

    it("generates a UUID", () -> {
      final String uuid1 = subject.makeUuid().toString();
      final String uuid2 = subject.makeUuid().toString();
      assertThat(uuid1.length(), equalTo(36));
      assertThat(uuid2.length(), equalTo(36));
      assertThat(uuid1, not(equalTo(uuid2)));
    });
  }
}
