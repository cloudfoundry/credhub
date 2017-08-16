package io.pivotal.security.domain;

import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.credential.RsaCredentialValue;
import io.pivotal.security.credential.SshCredentialValue;
import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.credential.UserCredentialValue;
import io.pivotal.security.request.CertificateGenerateRequest;
import io.pivotal.security.request.CertificateGenerationParameters;
import io.pivotal.security.request.PasswordGenerateRequest;
import io.pivotal.security.request.RsaGenerateRequest;
import io.pivotal.security.request.RsaGenerationParameters;
import io.pivotal.security.request.SshGenerateRequest;
import io.pivotal.security.request.SshGenerationParameters;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.request.UserGenerateRequest;
import io.pivotal.security.request.UsernameValue;
import io.pivotal.security.service.GeneratorService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

@RunWith(JUnit4.class)
public class CredentialValueFactoryTest {

  @Mock
  private GeneratorService generatorService;

  @Before
  public void beforeEach() {
    initMocks(this);
  }

  @Test
  public void generateValue_whenPassword_generatesPasswordValue() {
    PasswordGenerateRequest passwordRequestBody = new PasswordGenerateRequest();
    passwordRequestBody.setType("password");
    final StringGenerationParameters generationParameters = new StringGenerationParameters();
    passwordRequestBody.setGenerationParameters(generationParameters);

    when(generatorService.generatePassword(generationParameters))
        .thenReturn(new StringCredentialValue("luke's_password"));

    final CredentialValue credentialValue = CredentialValueFactory
        .generateValue(passwordRequestBody, generatorService);

    assertThat(credentialValue instanceof StringCredentialValue, equalTo(true));
    assertThat(((StringCredentialValue)credentialValue).getStringCredential(), equalTo("luke's_password"));
  }

  @Test
  public void generateValue_whenCertificate_generatesPasswordValue() {
    CertificateGenerateRequest certificateRequestBody = new CertificateGenerateRequest();
    certificateRequestBody.setType("certificate");
    final CertificateGenerationParameters generationParameters = new CertificateGenerationParameters();
    certificateRequestBody.setGenerationParameters(generationParameters);

    final CertificateCredentialValue certificateCredentialValue = new CertificateCredentialValue(
        "caCertificate", "certificate", "private_key", "ca_name");

    when(generatorService.generateCertificate(any()))
        .thenReturn(certificateCredentialValue);

    final CredentialValue credentialValue = CredentialValueFactory
        .generateValue(certificateRequestBody, generatorService);

    assertThat(credentialValue instanceof CertificateCredentialValue, equalTo(true));
    assertThat((credentialValue), equalTo(certificateCredentialValue));
  }

  @Test
  public void generateValue_whenRsa_generatesPasswordValue() {
    RsaGenerateRequest rsaRequestBody = new RsaGenerateRequest();
    rsaRequestBody.setType("rsa");
    final RsaGenerationParameters generationParameters = new RsaGenerationParameters();
    rsaRequestBody.setGenerationParameters(generationParameters);

    final RsaCredentialValue rsaCredentialValue = new RsaCredentialValue();
    when(generatorService.generateRsaKeys(generationParameters))
        .thenReturn(rsaCredentialValue);

    final CredentialValue credentialValue = CredentialValueFactory
        .generateValue(rsaRequestBody, generatorService);

    assertThat(credentialValue instanceof RsaCredentialValue, equalTo(true));
    assertThat((credentialValue), equalTo(rsaCredentialValue));
  }

  @Test
  public void generateValue_whenSsh_generatesPasswordValue() {
    SshGenerateRequest sshRequestBody = new SshGenerateRequest();
    sshRequestBody.setType("ssh");
    final SshGenerationParameters generationParameters = new SshGenerationParameters();
    sshRequestBody.setGenerationParameters(generationParameters);

    final SshCredentialValue sshCredentialValue = new SshCredentialValue();
    when(generatorService.generateSshKeys(generationParameters))
        .thenReturn(sshCredentialValue);

    final CredentialValue credentialValue = CredentialValueFactory
        .generateValue(sshRequestBody, generatorService);

    assertThat(credentialValue instanceof SshCredentialValue, equalTo(true));
    assertThat((credentialValue), equalTo(sshCredentialValue));
  }

  @Test
  public void generateValue_whenUserAndUsernameInValue_generatesUserValue() {
    final UsernameValue usernameValue = new UsernameValue();
    usernameValue.setUsername("luke");

    UserGenerateRequest userRequestBody = new UserGenerateRequest();
    userRequestBody.setType("user");
    userRequestBody.setValue(usernameValue);

    final UserCredentialValue userCredentialValue = new UserCredentialValue();
    when(generatorService.generateUser(eq("luke"), any(StringGenerationParameters.class)))
        .thenReturn(userCredentialValue);

    final CredentialValue credentialValue = CredentialValueFactory
        .generateValue(userRequestBody, generatorService);

    assertThat(credentialValue instanceof UserCredentialValue, equalTo(true));
    assertThat(credentialValue, equalTo(userCredentialValue));
  }
}
