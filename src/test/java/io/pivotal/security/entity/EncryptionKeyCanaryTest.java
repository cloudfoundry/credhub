package io.pivotal.security.entity;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

import com.greghaskins.spectrum.Spectrum;
import java.util.UUID;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class EncryptionKeyCanaryTest {

  {
    describe("#setEncryptionKeyUuid", () -> {
      it("should set the UUID", () -> {
        EncryptionKeyCanary subject = new EncryptionKeyCanary();
        UUID uuid = UUID.randomUUID();

        subject.setEncryptionKeyUuid(uuid);

        assertThat(subject.getUuid(), equalTo(uuid));
      });
    });
  }
}
