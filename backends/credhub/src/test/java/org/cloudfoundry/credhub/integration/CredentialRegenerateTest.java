package org.cloudfoundry.credhub.integration;

import java.time.Instant;
import java.util.function.Consumer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.data.EncryptionKeyCanaryDataService;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.domain.RsaCredentialVersion;
import org.cloudfoundry.credhub.domain.SshCredentialVersion;
import org.cloudfoundry.credhub.domain.UserCredentialVersion;
import org.cloudfoundry.credhub.entities.EncryptionKeyCanary;
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData;
import org.cloudfoundry.credhub.requests.StringGenerationParameters;
import org.cloudfoundry.credhub.services.CredentialVersionDataService;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_ACTOR_ID;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_TOKEN;
import static org.cloudfoundry.credhub.TestHelper.mockOutCurrentTimeProvider;
import static org.cloudfoundry.credhub.helpers.RequestHelper.expect404WhileRegeneratingCertificate;
import static org.cloudfoundry.credhub.helpers.RequestHelper.generateCa;
import static org.cloudfoundry.credhub.helpers.RequestHelper.generateCertificate;
import static org.cloudfoundry.credhub.helpers.RequestHelper.grantPermissions;
import static org.cloudfoundry.credhub.helpers.RequestHelper.revokePermissions;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(
  value = {
    "unit-test",
    "unit-test-permissions",
  },
  resolver = DatabaseProfileResolver.class
)
@SpringBootTest(classes = CredhubTestApp.class)
@Transactional
@SuppressFBWarnings(
  value = "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE",
  justification = "Let's refactor this class into kotlin"
)
public class CredentialRegenerateTest {
  private static final Instant FROZEN_TIME = Instant.ofEpochSecond(1400011001L);

  @Autowired
  private WebApplicationContext webApplicationContext;

  @Autowired
  private CredentialVersionDataService credentialVersionDataService;

  @Autowired
  private EncryptionKeyCanaryDataService canaryDataService;

  @Autowired
  private Encryptor encryptor;

  @MockBean
  private CurrentTimeProvider mockCurrentTimeProvider;

  private MockMvc mockMvc;
  private Consumer<Long> fakeTimeSetter;

  @Before
  public void beforeEach() {
    fakeTimeSetter = mockOutCurrentTimeProvider(mockCurrentTimeProvider);

    fakeTimeSetter.accept(FROZEN_TIME.toEpochMilli());
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();
  }

  @Test
  public void regeneratingAPassword_regeneratesThePassword() throws Exception {
    final PasswordCredentialVersion originalCredential = new PasswordCredentialVersion("/my-password");
    originalCredential.setEncryptor(encryptor);
    final StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setExcludeNumber(true);
    originalCredential
      .setPasswordAndGenerationParameters("original-password", generationParameters);
    originalCredential.setVersionCreatedAt(FROZEN_TIME.plusSeconds(1));

    credentialVersionDataService.save(originalCredential);

    fakeTimeSetter.accept(FROZEN_TIME.plusSeconds(10).toEpochMilli());

    final MockHttpServletRequestBuilder request = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{\"regenerate\":true,\"name\":\"my-password\"}");

    mockMvc.perform(request)
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.type").value("password"))
      .andExpect(jsonPath("$.version_created_at").value(FROZEN_TIME.plusSeconds(10).toString()));

    final PasswordCredentialVersion newPassword = (PasswordCredentialVersion) credentialVersionDataService.findMostRecent("/my-password");

    assertThat(newPassword.getPassword(), not(equalTo("original-credential")));
    assertThat(newPassword.getGenerationParameters().isExcludeNumber(), equalTo(true));
  }

  @Test
  public void regeneratingAnRsaKey_regeneratesTheRsaKey() throws Exception {
    final RsaCredentialVersion originalCredential = new RsaCredentialVersion("/my-rsa");
    originalCredential.setEncryptor(encryptor);
    originalCredential.setPrivateKey("original value");
    originalCredential.setVersionCreatedAt(FROZEN_TIME.plusSeconds(1));

    credentialVersionDataService.save(originalCredential);

    fakeTimeSetter.accept(FROZEN_TIME.plusSeconds(10).toEpochMilli());

    final MockHttpServletRequestBuilder request = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{\"regenerate\":true,\"name\":\"my-rsa\"}");

    mockMvc.perform(request)
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.type").value("rsa"))
      .andExpect(
        jsonPath("$.version_created_at").value(FROZEN_TIME.plusSeconds(10).toString()));

    final RsaCredentialVersion newRsa = (RsaCredentialVersion) credentialVersionDataService.findMostRecent("/my-rsa");

    assertTrue(newRsa.getPublicKey().contains("-----BEGIN PUBLIC KEY-----"));
    assertTrue(newRsa.getPrivateKey().contains("-----BEGIN RSA PRIVATE KEY-----"));
    assertThat(originalCredential.getPublicKey(), not(equalTo(newRsa.getPublicKey())));
    assertThat(originalCredential.getPrivateKey(), not(equalTo(newRsa.getPrivateKey())));
  }

  @Test
  public void regeneratingAnSshKey_regeneratesTheSshKey() throws Exception {
    final SshCredentialVersion originalCredential = new SshCredentialVersion("/my-ssh");
    originalCredential.setEncryptor(encryptor);
    originalCredential.setPrivateKey("original value");
    originalCredential.setVersionCreatedAt(FROZEN_TIME.plusSeconds(1));

    credentialVersionDataService.save(originalCredential);

    fakeTimeSetter.accept(FROZEN_TIME.plusSeconds(10).toEpochMilli());

    final MockHttpServletRequestBuilder request = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{\"regenerate\":true,\"name\":\"my-ssh\"}");

    mockMvc.perform(request)
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.type").value("ssh"))
      .andExpect(jsonPath("$.version_created_at").value(FROZEN_TIME.plusSeconds(10).toString()));

    final SshCredentialVersion newSsh = (SshCredentialVersion) credentialVersionDataService.findMostRecent("/my-ssh");

    assertThat(newSsh.getPrivateKey(), containsString("-----BEGIN RSA PRIVATE KEY-----"));
    assertThat(newSsh.getPublicKey(), containsString("ssh-rsa "));
    assertThat(newSsh.getPrivateKey(), not(equalTo(originalCredential.getPrivateKey())));
    assertThat(newSsh.getPublicKey(), not(equalTo(originalCredential.getPublicKey())));
  }

  @Test
  public void regeneratingAUser_regeneratesTheUser() throws Exception {
    final UserCredentialVersion originalCredential = new UserCredentialVersion("/the-user");
    originalCredential.setEncryptor(encryptor);
    final StringGenerationParameters generationParameters = new StringGenerationParameters();
    generationParameters.setExcludeNumber(true);
    generationParameters.setUsername("Darth Vader");
    originalCredential.setPassword("original-password");
    originalCredential.setUsername("Darth Vader");
    originalCredential.setSalt("pepper");
    originalCredential.setGenerationParameters(generationParameters);
    originalCredential.setVersionCreatedAt(FROZEN_TIME.plusSeconds(1));

    credentialVersionDataService.save(originalCredential);

    fakeTimeSetter.accept(FROZEN_TIME.plusSeconds(10).toEpochMilli());

    final MockHttpServletRequestBuilder request = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{\"regenerate\":true,\"name\":\"the-user\"}");

    mockMvc.perform(request)
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.type").value("user"))
      .andExpect(jsonPath("$.version_created_at").value(FROZEN_TIME.plusSeconds(10).toString()));

    final UserCredentialVersion newUser = (UserCredentialVersion) credentialVersionDataService.findMostRecent("/the-user");

    assertThat(newUser.getPassword(), not(equalTo(originalCredential.getPassword())));
    assertThat(newUser.getGenerationParameters().isExcludeNumber(), equalTo(true));
    assertThat(newUser.getUsername(), equalTo(originalCredential.getUsername()));
  }

  @Test
  public void regeneratingACredentialThatDoesNotExist_returnsAnError() throws Exception {
    final MockHttpServletRequestBuilder request = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{\"regenerate\":true,\"name\":\"my-password\"}");

    final String notFoundJson = "{" +
      "  \"error\": \"The request could not be completed because the credential does not exist or you do not have sufficient authorization.\"" +
      "}";

    mockMvc.perform(request)
      .andExpect(status().isNotFound())
      .andExpect(content().json(notFoundJson));
  }

  @Test
  public void regeneratingANonGeneratedPassword_returnsAnError() throws Exception {
    final PasswordCredentialVersion originalCredential = new PasswordCredentialVersion("/my-password");
    originalCredential.setEncryptor(encryptor);
    originalCredential.setPasswordAndGenerationParameters("abcde", null);

    credentialVersionDataService.save(originalCredential);

    final String cannotRegenerateJson = "{" +
      "  \"error\": \"The password could not be regenerated because the value was " +
      "statically set. Only generated passwords may be regenerated.\"" +
      "}";

    final MockHttpServletRequestBuilder request = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{\"regenerate\":true,\"name\":\"my-password\"}");

    mockMvc.perform(request)
      .andExpect(content().json(cannotRegenerateJson));
  }

  @Test
  public void regeneratingANonGeneratedUser_returnsAnError() throws Exception {
    final UserCredentialVersion originalCredential = new UserCredentialVersion("/my-user");
    originalCredential.setEncryptor(encryptor);
    originalCredential.setPassword("abcde");
    originalCredential.setUsername("username");
    originalCredential.setSalt("so salty");

    credentialVersionDataService.save(originalCredential);

    final String cannotRegenerateJson = "{" +
      "  \"error\": \"The user could not be regenerated because the value was" +
      " statically set. Only generated users may be regenerated.\"" +
      "}";

    final MockHttpServletRequestBuilder request = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{\"regenerate\":true,\"name\":\"my-user\"}");

    mockMvc.perform(request)
      .andExpect(content().json(cannotRegenerateJson));
  }

  @Test
  public void regeneratingAPasswordWithParametersThatCannotBeDecrypted_returnsAnError() throws Exception {
    final EncryptionKeyCanary encryptionKeyCanary = new EncryptionKeyCanary();
    canaryDataService.save(encryptionKeyCanary);

    final PasswordCredentialVersionData passwordCredentialData = new PasswordCredentialVersionData(
      "/my-password");
    final PasswordCredentialVersion originalCredential = new PasswordCredentialVersion(passwordCredentialData);
    originalCredential.setEncryptor(encryptor);
    originalCredential
      .setPasswordAndGenerationParameters("abcde", new StringGenerationParameters());

    passwordCredentialData.getEncryptedValueData().setEncryptionKeyUuid(encryptionKeyCanary.getUuid());

    credentialVersionDataService.save(originalCredential);

    // language=JSON
    final String cannotRegenerate = "{\n" +
      "  \"error\": \"The credential could not be accessed with the provided encryption keys. You must update your deployment configuration to continue" +
      ".\"\n" +
      "}";

    final MockHttpServletRequestBuilder request = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{\"regenerate\":true,\"name\":\"my-password\"}");

    mockMvc.perform(request)
      .andDo(print())
      .andExpect(status().isInternalServerError())
      .andExpect(content().json(cannotRegenerate));
  }

  @Test
  public void certificateRegeneration_whenUserNotAuthorizedToReadCa_shouldReturnCorrectError() throws Exception {
    generateCa(mockMvc, "ca", ALL_PERMISSIONS_TOKEN);

    grantPermissions(mockMvc, "/ca", ALL_PERMISSIONS_TOKEN, USER_A_ACTOR_ID, "read");

    generateCertificate(mockMvc, "/user-a/cert", "ca", USER_A_TOKEN);

    revokePermissions(mockMvc, "/ca", ALL_PERMISSIONS_TOKEN, USER_A_ACTOR_ID);

    expect404WhileRegeneratingCertificate(mockMvc, "/user-a/cert", USER_A_TOKEN,
      "The request could not be completed because the credential does not exist or you do not have sufficient authorization.");
  }
}
