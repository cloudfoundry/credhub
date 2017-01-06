package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.EncryptionKeyCanary;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.UUID;

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
