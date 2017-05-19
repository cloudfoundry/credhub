package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.config.EncryptionKeyMetadata;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.getBouncyCastleProvider;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(Spectrum.class)
public class BcEncryptionServiceTest {

  {
    it("should created a password-based key proxy", () -> {
      BcEncryptionService subject = new BcEncryptionService(getBouncyCastleProvider());

      EncryptionKeyMetadata keyMetadata = new EncryptionKeyMetadata();
      keyMetadata.setEncryptionPassword("foobar");

      final KeyProxy keyProxy = subject.createKeyProxy(keyMetadata);
      assertThat(keyProxy, instanceOf(PasswordBasedKeyProxy.class));
    });
  }
}
