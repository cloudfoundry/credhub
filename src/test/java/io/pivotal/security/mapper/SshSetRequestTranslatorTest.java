package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedSshSecret;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.*;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles("unit-test")
public class SshSetRequestTranslatorTest {
  @Autowired
  private Configuration jsonConfiguration;

  private SshSetRequestTranslator subject;

  private NamedSshSecret entity;

  {
    wireAndUnwire(this);

    describe("populating entity from json", () -> {

      beforeEach(() -> {
        subject = new SshSetRequestTranslator();
        entity = new NamedSshSecret("Foo");
      });

      it("creates an entity when all fields are present", () -> {
        checkEntity("my-public-key", "my-private-key", "my-public-key", "my-private-key");
      });

    });

  }

  private void checkEntity(String expectedPublicKey, String expectedPrivateKey, String actualPublicKey, String actualPrivateKey) {
    String requestJson = createJson(actualPublicKey, actualPrivateKey);
    DocumentContext parsed = JsonPath.using(jsonConfiguration).parse(requestJson);
    subject.populateEntityFromJson(entity, parsed);
    assertThat(entity.getPublicKey(), equalTo(expectedPublicKey));
    assertThat(entity.getPrivateKey(), equalTo(expectedPrivateKey));
  }

  private String createJson(String publicKey, String privateKey) {
    return "{\"type\":\"ssh\",\"value\":{\"public_key\":\"" + publicKey + "\",\"private_key\":\"" + privateKey + "\"}}";
  }
}