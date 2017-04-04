package io.pivotal.security.mapper;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.request.SshGenerationParameters;
import io.pivotal.security.controller.v1.SshSecretParametersFactory;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.generator.SshGenerator;
import io.pivotal.security.secret.SshKey;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SshGeneratorRequestTranslatorTest {

  @Autowired
  ParseContext jsonPath;

  @MockBean
  SshGenerator secretGenerator;

  @MockBean
  SshSecretParametersFactory sshSecretParametersFactory;

  @Autowired
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @Autowired
  private SshGeneratorRequestTranslator subject;

  private SshGenerationParameters mockParams;

  private ArgumentCaptor<SshGenerationParameters> secretParameterCaptor;

  @Autowired
  private Encryptor encryptor;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockParams = spy(SshGenerationParameters.class);
      when(sshSecretParametersFactory.get()).thenReturn(mockParams);
    });

    describe("validateJsonKeys", () -> {
      it("accepts valid keys", () -> {
        String requestBody = "{"
            + "\"type\":\"ssh\","
            + "\"name\":\"xyzzy\","
            + "\"overwrite\":false,"
            + "\"regenerate\":true,"
            + "\"parameters\":{"
            + "\"key_length\":3072,"
            + "\"ssh_comment\":\"commentcommentcomment\""
            + "}"
            + "}";
        DocumentContext parsed = jsonPath.parse(requestBody);

        subject.validateJsonKeys(parsed);
        //pass
      });

      itThrowsWithMessage("should throw if given invalid keys",
          ParameterizedValidationException.class, "error.invalid_json_key", () -> {
            String requestBody = "{\"type\":\"ssh\",\"foo\":\"invalid\"}";
            DocumentContext parsed = jsonPath.parse(requestBody);

            subject.validateJsonKeys(parsed);
          });
    });

    describe("populateEntityFromJson", () -> {
      beforeEach(() -> {
        secretParameterCaptor = ArgumentCaptor.forClass(SshGenerationParameters.class);
        when(secretGenerator.generateSecret(secretParameterCaptor.capture()))
            .thenReturn(new SshKey("my-public", "my-private", null));
      });

      it("populates an entity", () -> {
        String json = "{\"type\":\"ssh\"}";
        DocumentContext parsed = jsonPath.parse(json);

        NamedSshSecret namedSshSecret = new NamedSshSecret();
        namedSshSecret.setEncryptor(encryptor);
        subject.populateEntityFromJson(namedSshSecret, parsed);

        verify(secretGenerator).generateSecret(mockParams);

        assertThat(namedSshSecret.getPrivateKey(), equalTo("my-private"));
        assertThat(namedSshSecret.getPublicKey(), equalTo("my-public"));
      });

      it("validates the parameters", () -> {
        String json = "{\"type\":\"ssh\"}";
        DocumentContext parsed = jsonPath.parse(json);

        NamedSshSecret namedSshSecret = new NamedSshSecret();
        namedSshSecret.setEncryptor(encryptor);
        subject.populateEntityFromJson(namedSshSecret, parsed);

        verify(mockParams, times(1)).validate();
      });

      it("accepts parameters", () -> {
        String json = "{"
            + "\"type\":\"ssh\","
            + "\"parameters\":{"
            + "\"key_length\":3072,"
            + "\"ssh_comment\":\"this is an ssh comment\""
            + "}"
            + "}";
        DocumentContext parsed = jsonPath.parse(json);

        NamedSshSecret namedSshSecret = new NamedSshSecret();
        namedSshSecret.setEncryptor(encryptor);
        subject.populateEntityFromJson(namedSshSecret, parsed);

        verify(mockParams).setKeyLength(3072);
        verify(mockParams).setSshComment("this is an ssh comment");

        verify(secretGenerator).generateSecret(mockParams);
      });

      it("can regenerate using the existing entity and JSON", () -> {
        String sshPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDI2N6/Mn0"
            + "S11V+zqxOBF5ZF8lpHPhbrEqV3g8SNkCS4MhDD/KZcAKEaV80qdm6uDFQkKv6Xd"
            + "lHy7HWsxaFq05RM0pOoZU2P2SWGI9FXP9yCqzwTQebF5xi3CHuhHXjndnRCXJtC"
            + "/gZvf5y2vXga/cSWWMgZFok42Jf1EMw8GOMF4373th/ApwHLuxoo965EKVaPsbg"
            + "JjOOS6YmI3TImtZAInR0bWKSNP0/J9Il6TluelR2BKE8k/KRSSgBZgOLL5XSI3V"
            + "HNfyBoU99HRn94pyYftrg6Pa0A8gdwD4GopYwidvNyRLoCrocl5kcnNdCzJ6qdA"
            + "U4wEAq/wYxN71mfZY5zqG2LbJGXLxc0hfR4mkdxb60xTuLrNHVnS0BdIy2SB+ft"
            + "QeNHwsmAhqkQa6Sg5GPIDLUh84ir1wnXog6Px8yw2UzCgGB9PekP2N0X0iYsjls"
            + "qI/e9B3C7fWoDDlzfmhHsVtWmxcABBRGyFAS5quPP4guuqADjuUjEJAWVUl7a+0"
            + "= foocomment";

        NamedSshSecret secret = new NamedSshSecret("test");

        secret.setEncryptor(encryptor);
        secret.setPublicKey(sshPublicKey);
        secret.setEncryptionKeyUuid(encryptionKeyCanaryMapper.getActiveUuid());
        secret.setPrivateKey("fakeprivatekey");

        subject.populateEntityFromJson(secret, jsonPath.parse("{\"regenerate\":true}"));

        SshGenerationParameters secretParameters = secretParameterCaptor.getValue();
        assertThat(secretParameters.getKeyLength(), equalTo(3072));
        assertThat(secretParameters.getSshComment(), equalTo("foocomment"));
      });
    });
  }
}
