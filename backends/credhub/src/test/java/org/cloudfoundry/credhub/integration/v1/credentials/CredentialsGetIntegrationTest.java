package org.cloudfoundry.credhub.integration.v1.credentials;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import org.cloudfoundry.credhub.AuthConstants;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.TestHelper;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.ValueCredentialVersion;
import org.cloudfoundry.credhub.exceptions.KeyNotFoundException;
import org.cloudfoundry.credhub.services.CredentialVersionDataService;
import org.cloudfoundry.credhub.services.DefaultPermissionedCredentialService;
import org.cloudfoundry.credhub.services.PermissionCheckingService;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.cloudfoundry.credhub.utils.TestConstants;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static com.google.common.collect.Lists.newArrayList;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
public class CredentialsGetIntegrationTest {

  private static final Instant FROZEN_TIME = Instant.ofEpochSecond(1400011001L);
  private static final String CREDENTIAL_NAME = "/my-namespace/controllerGetTest/credential-name";
  private static final String CREDENTIAL_VALUE = "test value";

  @Autowired
  private WebApplicationContext webApplicationContext;

  @SpyBean
  private Encryptor encryptor;

  @SpyBean
  private PermissionCheckingService permissionCheckingService;

  @SpyBean
  private CredentialVersionDataService credentialVersionDataService;

  @SpyBean
  private DefaultPermissionedCredentialService permissionedCredentialService;

  @MockBean
  private CurrentTimeProvider mockCurrentTimeProvider;

  private MockMvc mockMvc;

  @Before
  public void beforeEach() {
    final Consumer<Long> fakeTimeSetter = TestHelper.mockOutCurrentTimeProvider(mockCurrentTimeProvider);

    fakeTimeSetter.accept(FROZEN_TIME.toEpochMilli());

    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();

    permissionedCredentialService.setConcatenateCas(false);
  }

  @Test
  public void gettingACredential_byName_thatExists_returnsTheCredential() throws Exception {
    doReturn(true)
      .when(permissionCheckingService).hasPermission(any(String.class),
      any(String.class), eq(PermissionOperation.READ));

    final UUID uuid = UUID.randomUUID();

    final ValueCredentialVersion credential = new ValueCredentialVersion(CREDENTIAL_NAME);
    credential.setEncryptor(encryptor);
    credential.setUuid(uuid);
    credential.setVersionCreatedAt(FROZEN_TIME);
    credential.getCredential().setUuid(UUID.randomUUID());

    doReturn(CREDENTIAL_VALUE).when(encryptor).decrypt(any());

    doReturn(newArrayList(credential)).when(credentialVersionDataService).findAllByName(CREDENTIAL_NAME);

    final MockHttpServletRequestBuilder request = get("/api/v1/data?name=" + CREDENTIAL_NAME)
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    mockMvc.perform(request)
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.data[0]" + ".type").value("value"))
      .andExpect(jsonPath("$.data[0]" + ".value").value(CREDENTIAL_VALUE))
      .andExpect(jsonPath("$.data[0]" + ".id").value(uuid.toString()))
      .andExpect(jsonPath("$.data[0]" + ".version_created_at").value(FROZEN_TIME.toString()));
  }

  @Test
  public void gettingACredential_byName_thatExists_withoutLeadingSlash_returnsTheCredential() throws Exception {
    doReturn(true)
      .when(permissionCheckingService).hasPermission(any(String.class),
      any(String.class), eq(PermissionOperation.READ));

    final UUID uuid = UUID.randomUUID();

    final ValueCredentialVersion credential = new ValueCredentialVersion(CREDENTIAL_NAME);
    credential.setEncryptor(encryptor);
    credential.setUuid(uuid);
    credential.setVersionCreatedAt(FROZEN_TIME);
    credential.getCredential().setUuid(UUID.randomUUID());

    doReturn(CREDENTIAL_VALUE).when(encryptor).decrypt(any());

    doReturn(newArrayList(credential)).when(credentialVersionDataService).findAllByName(CREDENTIAL_NAME);

    final MockHttpServletRequestBuilder request = get("/api/v1/data?name=" + CREDENTIAL_NAME)
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    mockMvc.perform(request)
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.data[0]" + ".value").value(CREDENTIAL_VALUE));
  }

  @Test
  public void gettingACredential_byName_whenTheCredentialDoesNotExist_returnsNotFound() throws Exception {
    doReturn(true)
      .when(permissionCheckingService).hasPermission(any(String.class),
      any(String.class), eq(PermissionOperation.READ));

    final MockHttpServletRequestBuilder get1 = get("/api/v1/data?name=invalid_name")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    final String expectedError1 = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";
    mockMvc.perform(get1)
      .andExpect(status().isNotFound())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(
        jsonPath("$.error").value(expectedError1)
      );
  }

  @Test
  public void gettingACredential_byName_whenTheCredentialDoesNotExist_andCurrentIsSetToTrue_returnsNotFound()
    throws Exception {
    doReturn(true)
      .when(permissionCheckingService).hasPermission(any(String.class),
      any(String.class), eq(PermissionOperation.READ));

    final MockHttpServletRequestBuilder get1 = get("/api/v1/data?name=invalid_name&current=true")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    final String expectedError1 = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";
    mockMvc.perform(get1)
      .andExpect(status().isNotFound())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(
        jsonPath("$.error").value(expectedError1)
      );
  }

  @Test
  public void gettingACredential_byName_whenTheUserDoesNotHavePermissionToAccessTheCredential_returnsNotFound()
    throws Exception {
    doReturn(false)
      .when(permissionCheckingService).hasPermission(any(String.class),
      any(String.class), eq(PermissionOperation.READ));
    final MockHttpServletRequestBuilder get1 = get("/api/v1/data?name=" + CREDENTIAL_NAME)
      .header("Authorization", "Bearer " + AuthConstants.NO_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    final ResultActions response = mockMvc.perform(get1);

    final String expectedError = "The request could not be completed because the credential does not exist or you do not have sufficient authorization.";

    response
      .andExpect(status().isNotFound())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void gettingACredential_byName_withCurrentSetToTrue_returnsTheLatestCredential() throws Exception {
    setUpCredential();

    mockMvc.perform(get("/api/v1/data?current=true&name=" + CREDENTIAL_NAME)
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.data", hasSize(1)));

    verify(credentialVersionDataService).findActiveByName(CREDENTIAL_NAME);
  }

  @Test
  public void gettingACredential_byName_withCurrentSetToFalse_returnsAllTheCredentialVersions() throws Exception {
    final UUID uuid = UUID.randomUUID();

    final ValueCredentialVersion valueCredential1 = new ValueCredentialVersion(CREDENTIAL_NAME);
    valueCredential1.setEncryptor(encryptor);
    valueCredential1.setUuid(uuid);
    valueCredential1.setVersionCreatedAt(FROZEN_TIME);
    valueCredential1.getCredential().setUuid(UUID.randomUUID());

    final ValueCredentialVersion valueCredential2 = new ValueCredentialVersion(CREDENTIAL_NAME);
    valueCredential2.setEncryptor(encryptor);
    valueCredential2.setUuid(uuid);
    valueCredential2.setVersionCreatedAt(FROZEN_TIME);
    valueCredential2.getCredential().setUuid(UUID.randomUUID());

    doReturn(CREDENTIAL_VALUE).when(encryptor).decrypt(any());

    doReturn(
      newArrayList(valueCredential1, valueCredential2)
    ).when(credentialVersionDataService).findAllByName(CREDENTIAL_NAME);

    mockMvc.perform(get("/api/v1/data?current=false&name=" + CREDENTIAL_NAME)
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.data", hasSize(equalTo(2))));
  }

  @Test
  public void gettingACredential_byName_withCurrentSetToFalse_andNumberOfVersions_returnsTheSpecifiedNumberOfVersions()
    throws Exception {
    final UUID uuid = UUID.randomUUID();

    final Instant credential1Instant = Instant.ofEpochSecond(1400000001L);
    final Instant credential2Instant = Instant.ofEpochSecond(1400000002L);
    final Instant credential3Instant = Instant.ofEpochSecond(1400000003L);

    final ValueCredentialVersion valueCredential1 = new ValueCredentialVersion(CREDENTIAL_NAME);
    valueCredential1.setEncryptor(encryptor);
    valueCredential1.setUuid(uuid);
    valueCredential1.setVersionCreatedAt(credential1Instant);
    valueCredential1.getCredential().setUuid(UUID.randomUUID());

    final ValueCredentialVersion valueCredential2 = new ValueCredentialVersion(CREDENTIAL_NAME);
    valueCredential2.setEncryptor(encryptor);
    valueCredential2.setUuid(uuid);
    valueCredential2.setVersionCreatedAt(credential2Instant);
    valueCredential2.getCredential().setUuid(UUID.randomUUID());

    final ValueCredentialVersion valueCredential3 = new ValueCredentialVersion(CREDENTIAL_NAME);
    valueCredential3.setEncryptor(encryptor);
    valueCredential3.setUuid(uuid);
    valueCredential3.setVersionCreatedAt(credential3Instant);
    valueCredential3.getCredential().setUuid(UUID.randomUUID());

    doReturn(CREDENTIAL_VALUE).when(encryptor).decrypt(any());

    doReturn(
      newArrayList(valueCredential1, valueCredential2)
    ).when(credentialVersionDataService).findNByName(CREDENTIAL_NAME, 2);

    mockMvc.perform(get("/api/v1/data?current=false&name=" + CREDENTIAL_NAME + "&versions=2")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.data", hasSize(equalTo(2))))
      .andExpect(jsonPath("$.data[0].version_created_at", equalTo(credential1Instant.toString())))
      .andExpect(jsonPath("$.data[1].version_created_at", equalTo(credential2Instant.toString())));
  }

  @Test
  public void gettingACredential_byName_returnsAnErrorWhenTheNameIsNotGiven() throws Exception {
    final MockHttpServletRequestBuilder get = get("/api/v1/data?name=")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    mockMvc.perform(get)
      .andExpect(status().is4xxClientError())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(
        jsonPath("$.error")
          .value("The query parameter name is required for this request.")
      );
  }

  @Test
  public void gettingACredential_byId_returnsTheCredential() throws Exception {
    final UUID uuid = UUID.randomUUID();
    final ValueCredentialVersion credential = new ValueCredentialVersion(CREDENTIAL_NAME);
    credential.setEncryptor(encryptor);
    credential.setUuid(uuid);
    credential.setVersionCreatedAt(FROZEN_TIME);

    doReturn(CREDENTIAL_VALUE).when(encryptor).decrypt(any());
    doReturn(credential).when(credentialVersionDataService).findByUuid(uuid.toString());

    final MockHttpServletRequestBuilder request = get("/api/v1/data/" + uuid)
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    mockMvc.perform(request)
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.type").value("value"))
      .andExpect(jsonPath("$.value").value(CREDENTIAL_VALUE))
      .andExpect(jsonPath("$.id").value(uuid.toString()))
      .andExpect(jsonPath("$.version_created_at").value(FROZEN_TIME.toString()));
  }

  @Test
  public void gettingACredential_thatIsEncryptedWithAnUnknownKey_throwsAnException() throws Exception {
    final UUID uuid = UUID.randomUUID();
    final ValueCredentialVersion valueCredential = new ValueCredentialVersion(CREDENTIAL_NAME);
    valueCredential.setEncryptor(encryptor);
    valueCredential.setUuid(uuid);
    valueCredential.setVersionCreatedAt(FROZEN_TIME);
    valueCredential.getCredential().setUuid(UUID.randomUUID());

    doThrow(new KeyNotFoundException(ErrorMessages.MISSING_ENCRYPTION_KEY))
      .when(encryptor).decrypt(any());
    doReturn(Collections.singletonList(valueCredential)).when(credentialVersionDataService)
      .findAllByName(CREDENTIAL_NAME);

    final MockHttpServletRequestBuilder get =
      get("/api/v1/data?name=" + CREDENTIAL_NAME)
        .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON);

    final String expectedError = "The credential could not be accessed with the provided encryption keys. You must update your deployment configuration to continue.";

    mockMvc.perform(get)
      .andExpect(status().isInternalServerError())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void providingCurrentTrueAndVersions_throwsAnException() throws Exception {
    final MockHttpServletRequestBuilder get =
      get("/api/v1/data?name=" + CREDENTIAL_NAME + "&current=true&versions=45")
        .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
        .accept(APPLICATION_JSON);

    mockMvc.perform(get)
      .andExpect(status().isBadRequest())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.error")
        .value("The query parameters current and versions cannot be provided in the same request."));
  }

  @Test
  public void gettingACertificateCredential_byName_whenConcatenateCasIsTrue_returnsTheCredential_withConcatenatedCas() throws Exception {
    permissionedCredentialService.setConcatenateCas(true);
    final UUID uuid = UUID.randomUUID();
    final CertificateCredentialVersion certificate = new CertificateCredentialVersion(CREDENTIAL_NAME);
    certificate.setEncryptor(encryptor);
    certificate.setUuid(uuid);
    certificate.setVersionCreatedAt(FROZEN_TIME);
    certificate.setCa(TestConstants.TEST_CERTIFICATE);
    certificate.setCaName("/some-ca");
    certificate.setCertificate(TestConstants.TEST_CERTIFICATE);
    certificate.getCredential().setUuid(uuid);

    doReturn(CREDENTIAL_VALUE).when(encryptor).decrypt(any());

    CertificateCredentialVersion credentialVersion1 = new CertificateCredentialVersion("/some-ca");
    CertificateCredentialVersion credentialVersion2 = new CertificateCredentialVersion("/some-ca");
    credentialVersion1.setCertificate(TestConstants.TEST_CERTIFICATE);
    credentialVersion2.setCertificate(TestConstants.OTHER_TEST_CERTIFICATE);
    List<CredentialVersion> credentialVersionList = Arrays.asList(credentialVersion1, credentialVersion2);

    doReturn(Collections.singletonList(certificate)).when(credentialVersionDataService).findAllByName(CREDENTIAL_NAME);
    doReturn(credentialVersionList).when(credentialVersionDataService).findActiveByName("/some-ca");

    final MockHttpServletRequestBuilder request = get("/api/v1/data?name=" + CREDENTIAL_NAME)
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    mockMvc.perform(request)
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.data[0].type").value("certificate"))
      .andExpect(jsonPath("$.data[0].value.certificate").value(TestConstants.TEST_CERTIFICATE))
      .andExpect(jsonPath("$.data[0].id").value(uuid.toString()))
      .andExpect(jsonPath("$.data[0].version_created_at").value(FROZEN_TIME.toString()))
      .andExpect(jsonPath("$.data[0].value.ca").value(TestConstants.TEST_CERTIFICATE + "\n" + TestConstants.OTHER_TEST_CERTIFICATE));
  }

  @Test
  public void gettingACertificateCredential_byName_whenConcatenateCasIsFalse_returnsTheCredential_withoutConcatenatedCas() throws Exception {
    permissionedCredentialService.setConcatenateCas(false);
    final UUID uuid = UUID.randomUUID();
    final CertificateCredentialVersion certificate = new CertificateCredentialVersion(CREDENTIAL_NAME);
    certificate.setEncryptor(encryptor);
    certificate.setUuid(uuid);
    certificate.setVersionCreatedAt(FROZEN_TIME);
    certificate.setCa(TestConstants.TEST_CERTIFICATE);
    certificate.setCaName("/some-ca");
    certificate.setCertificate(TestConstants.TEST_CERTIFICATE);
    certificate.getCredential().setUuid(uuid);

    doReturn(CREDENTIAL_VALUE).when(encryptor).decrypt(any());

    CertificateCredentialVersion credentialVersion1 = new CertificateCredentialVersion("/some-ca");
    CertificateCredentialVersion credentialVersion2 = new CertificateCredentialVersion("/some-ca");
    credentialVersion1.setCertificate(TestConstants.TEST_CERTIFICATE);
    credentialVersion2.setCertificate(TestConstants.OTHER_TEST_CERTIFICATE);
    List<CredentialVersion> credentialVersionList = Arrays.asList(credentialVersion1, credentialVersion2);

    doReturn(Collections.singletonList(certificate)).when(credentialVersionDataService).findAllByName(CREDENTIAL_NAME);
    doReturn(credentialVersionList).when(credentialVersionDataService).findActiveByName("/some-ca");

    final MockHttpServletRequestBuilder request = get("/api/v1/data?name=" + CREDENTIAL_NAME)
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    mockMvc.perform(request)
      .andExpect(status().isOk())
      .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
      .andExpect(jsonPath("$.data[0].type").value("certificate"))
      .andExpect(jsonPath("$.data[0].value.certificate").value(TestConstants.TEST_CERTIFICATE))
      .andExpect(jsonPath("$.data[0].id").value(uuid.toString()))
      .andExpect(jsonPath("$.data[0].version_created_at").value(FROZEN_TIME.toString()))
      .andExpect(jsonPath("$.data[0].value.ca").value(TestConstants.TEST_CERTIFICATE));
  }

  private void setUpCredential() {
    final UUID uuid = UUID.randomUUID();
    final ValueCredentialVersion credential = new ValueCredentialVersion(CREDENTIAL_NAME);
    credential.setEncryptor(encryptor);
    credential.setUuid(uuid);
    credential.setVersionCreatedAt(FROZEN_TIME);
    credential.getCredential().setUuid(UUID.randomUUID());

    doReturn(CREDENTIAL_VALUE).when(encryptor).decrypt(any());

    doReturn(Collections.singletonList(credential)).when(credentialVersionDataService).findActiveByName(CREDENTIAL_NAME);
  }
}
