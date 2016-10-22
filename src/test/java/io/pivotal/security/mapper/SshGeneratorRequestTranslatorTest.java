package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.controller.v1.SshSecretParameters;
import io.pivotal.security.controller.v1.SshSecretParametersFactory;
import io.pivotal.security.entity.NamedSshSecret;
import io.pivotal.security.generator.SshGenerator;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.SshSecret;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.*;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class SshGeneratorRequestTranslatorTest {

  @Autowired
  ParseContext jsonPath;

  @Mock
  SshGenerator secretGenerator;

  @Mock
  SshSecretParametersFactory sshSecretParametersFactory;

  @InjectMocks
  private SshGeneratorRequestTranslator subject;

  private SshSecretParameters mockParams;

  private ArgumentCaptor<SshSecretParameters> secretParameterCaptor;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockParams = spy(SshSecretParameters.class);
      when(sshSecretParametersFactory.get()).thenReturn(mockParams);
    });

    describe("validateJsonKeys", () -> {
      it("accepts valid keys", () -> {
        String requestBody = "{" +
            "\"type\":\"ssh\"," +
            "\"overwrite\":false," +
            "\"regenerate\":true," +
            "\"parameters\":{" +
              "\"key_length\":3072," +
              "\"ssh_comment\":\"commentcommentcomment\"" +
            "}" +
            "}";
        DocumentContext parsed = jsonPath.parse(requestBody);

        subject.validateJsonKeys(parsed);
        //pass
      });

      itThrowsWithMessage("should throw if given invalid keys", ParameterizedValidationException.class, "error.invalid_json_key", () -> {
        String requestBody = "{\"type\":\"ssh\",\"foo\":\"invalid\"}";
        DocumentContext parsed = jsonPath.parse(requestBody);

        subject.validateJsonKeys(parsed);
      });
    });

    describe("populateEntityFromJson", () -> {
      beforeEach(() -> {
        secretParameterCaptor = ArgumentCaptor.forClass(SshSecretParameters.class);
        when(secretGenerator.generateSecret(secretParameterCaptor.capture()))
            .thenReturn(new SshSecret(null, null, "my-public", "my-private"));
      });

      it("populates an entity", () -> {
        String json = "{\"type\":\"ssh\"}";
        DocumentContext parsed = jsonPath.parse(json);

        NamedSshSecret namedSshSecret = new NamedSshSecret();
        subject.populateEntityFromJson(namedSshSecret, parsed);

        verify(secretGenerator).generateSecret(mockParams);

        assertThat(namedSshSecret.getPrivateKey(), equalTo("my-private"));
        assertThat(namedSshSecret.getPublicKey(), equalTo("my-public"));
      });

      it("validates the parameters", () -> {
        String json = "{\"type\":\"ssh\"}";
        DocumentContext parsed = jsonPath.parse(json);

        NamedSshSecret namedSshSecret = new NamedSshSecret();
        subject.populateEntityFromJson(namedSshSecret, parsed);

        verify(mockParams, times(1)).validate();
      });

      it("accepts parameters", () -> {
        String json = "{" +
            "\"type\":\"ssh\"," +
            "\"parameters\":{" +
              "\"key_length\":3072," +
              "\"ssh_comment\":\"this is an ssh comment\"" +
            "}" +
          "}";
        DocumentContext parsed = jsonPath.parse(json);

        NamedSshSecret namedSshSecret = new NamedSshSecret();
        subject.populateEntityFromJson(namedSshSecret, parsed);

        verify(mockParams).setKeyLength(3072);
        verify(mockParams).setSshComment("this is an ssh comment");

        verify(secretGenerator).generateSecret(mockParams);
      });

      it("can regenerate using the existing entity and JSON", () -> {
        String sshPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDI2N6/Mn0S11V+zqxOBF5ZF8lpHPhbrEqV3g8SNkCS4MhDD/KZcAKEaV80qdm6uDFQkKv6XdlHy7HWsxaFq05RM0pOoZU2P2SWGI9FXP9yCqzwTQebF5xi3CHuhHXjndnRCXJtC/gZvf5y2vXga/cSWWMgZFok42Jf1EMw8GOMF4373th/ApwHLuxoo965EKVaPsbgJjOOS6YmI3TImtZAInR0bWKSNP0/J9Il6TluelR2BKE8k/KRSSgBZgOLL5XSI3VHNfyBoU99HRn94pyYftrg6Pa0A8gdwD4GopYwidvNyRLoCrocl5kcnNdCzJ6qdAU4wEAq/wYxN71mfZY5zqG2LbJGXLxc0hfR4mkdxb60xTuLrNHVnS0BdIy2SB+ftQeNHwsmAhqkQa6Sg5GPIDLUh84ir1wnXog6Px8yw2UzCgGB9PekP2N0X0iYsjlsqI/e9B3C7fWoDDlzfmhHsVtWmxcABBRGyFAS5quPP4guuqADjuUjEJAWVUl7a+0= foocomment";

        NamedSshSecret secret = new NamedSshSecret();
        secret.setName("test");
        secret.setPublicKey(sshPublicKey);
        secret.setPrivateKey("fakeprivatekey");

        subject.populateEntityFromJson(secret, jsonPath.parse("{\"regenerate\":true}"));

        SshSecretParameters secretParameters = secretParameterCaptor.getValue();
        assertThat(secretParameters.getKeyLength(), equalTo(3072));
        assertThat(secretParameters.getSshComment(), equalTo("foocomment"));
      });
    });
  }
}
