package io.pivotal.security.config;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class EncryptionKeysConfigurationTest {
  @Autowired
  private EncryptionKeysConfiguration subject;

  {
    wireAndUnwire(this, false);

    it("fills in list of keys from application-unit-test.yml", () -> {
      List<EncryptionKeyMetadata> keys = subject.getKeys();
      assertThat(keys.size(), equalTo(2));

      EncryptionKeyMetadata firstKey = keys.get(0);
      EncryptionKeyMetadata secondKey = keys.get(1);

      assertThat(firstKey.getDevKey(), equalTo("D673ACD01DA091B08144FBC8C0B5F524"));
      assertThat(firstKey.isActive(), equalTo(true));

      assertThat(secondKey.getDevKey(), equalTo("A673ACF01DB091B08133FBC8C0B5F555"));
      assertThat(secondKey.isActive(), equalTo(false));
    });
  }
}
