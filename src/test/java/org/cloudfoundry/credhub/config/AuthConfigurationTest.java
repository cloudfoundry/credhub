package org.cloudfoundry.credhub.config;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.cloudfoundry.credhub.data.PermissionDataService;
import org.cloudfoundry.credhub.data.RequestAuditRecordDataService;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.entity.RequestAuditRecord;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.cloudfoundry.credhub.util.AuthConstants;
import org.cloudfoundry.credhub.util.CertificateReader;
import org.cloudfoundry.credhub.util.CertificateStringConstants;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class AuthConfigurationTest {

  @Autowired
  WebApplicationContext applicationContext;

  @MockBean
  CredentialVersionDataService credentialVersionDataService;

  @MockBean
  PermissionDataService permissionDataService;

  @SpyBean
  RequestAuditRecordDataService requestAuditRecordDataService;

  private MockMvc mockMvc;

  private final String dataApiPath = "/api/v1/data";
  private final String credentialName = "test";

  @Before
  public void beforeEach() {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(applicationContext)
        .apply(springSecurity())
        .build();
  }

  @Test
  public void infoCanBeAccessedWithoutAuthentication()throws Exception {
    mockMvc.perform(get("/info").accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.auth-server.url").isNotEmpty());
  }

  @Test
  public void healthCanBeAccessWithoutAuthentication() throws Exception{
    mockMvc.perform(get("/health").accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").isNotEmpty());
  }

  @Test
  public void dataEndpointDeniesAccessWithoutAuthentication() throws Exception {
    setupDataEndpointMocks();

    mockMvc.perform(post(dataApiPath)
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"type\":\"password\",\"name\":\"" + credentialName + "\"}")
    ).andExpect(status().isUnauthorized());
  }

  @Test
  public void dataEndpoint_withAnAcceptedToken_allowsAccess() throws Exception {
    setupDataEndpointMocks();

    final MockHttpServletRequestBuilder post = post(dataApiPath)
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"type\":\"password\",\"name\":\"" + credentialName + "\"}");

    mockMvc.perform(post)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.type").value("password"))
        .andExpect(jsonPath("$.version_created_at").exists())
        .andExpect(jsonPath("$.value").exists());
  }

  @Test
  public void dataEndpoint_withTokenWithInsufficientScopes_disallowsAccess() throws Exception {
    setupDataEndpointMocks();

    final MockHttpServletRequestBuilder post = post(dataApiPath)
        .header("Authorization", "Bearer " + AuthConstants.INVALID_SCOPE_KEY_JWT)
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"type\":\"password\",\"name\":\"" + credentialName + "\"}");

    mockMvc.perform(post)
        .andExpect(status().isForbidden());

  }

  @Test
  public void dataEndpoint_withoutAToken_disallowsAccess() throws Exception {
    setupDataEndpointMocks();

    final MockHttpServletRequestBuilder post = post(dataApiPath)
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"type\":\"password\",\"name\":\"" + credentialName + "\"}");

    mockMvc.perform(post).andExpect(status().isUnauthorized());

  }

  @Test
  public void dataEndpoint_withMutualTLS_allowsAllClientCertsWithValidOrgUnitAndClientAuthExtensions()
      throws Exception {
    setupDataEndpointMocks();

    final MockHttpServletRequestBuilder post = post(dataApiPath)
        .with(SecurityMockMvcRequestPostProcessors
            .x509(CertificateReader.getCertificate(CertificateStringConstants.SELF_SIGNED_CERT_WITH_CLIENT_AUTH_EXT)))
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"type\":\"password\",\"name\":\"" + credentialName + "\"}");

    mockMvc.perform(post)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.type").value("password"))
        .andExpect(jsonPath("$.version_created_at").exists())
        .andExpect(jsonPath("$.value").exists());

  }

  @Test
  public void dataEndpoint_withMutualTLS_logsOrgUnitFromTheDN()
      throws Exception {
    setupDataEndpointMocks();

    final MockHttpServletRequestBuilder post = post(dataApiPath)
        .with(SecurityMockMvcRequestPostProcessors
            .x509(CertificateReader.getCertificate(CertificateStringConstants.SELF_SIGNED_CERT_WITH_CLIENT_AUTH_EXT)))
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"type\":\"password\",\"name\":\"" + credentialName + "\"}");

    mockMvc.perform(post)
        .andExpect(status().isOk());

    ArgumentCaptor<RequestAuditRecord> argumentCaptor = ArgumentCaptor.forClass(
        RequestAuditRecord.class
    );
    verify(requestAuditRecordDataService, times(1)).save(argumentCaptor.capture());

    RequestAuditRecord requestAuditRecord = argumentCaptor.getValue();
    assertThat(requestAuditRecord.getClientId(), equalTo(
        "C=US,ST=NY,O=Test Org,OU=app:a12345e5-b2b0-4648-a0d0-772d3d399dcb,CN=example.com,E=test@example.com"));
  }

  @Test
  public void dataEndpoint_withMutualTLS_deniesClientCertsWithOrgUnitsThatDontContainV4UUID()
      throws Exception {
    setupDataEndpointMocks();

    final MockHttpServletRequestBuilder post = post(dataApiPath)
        .with(SecurityMockMvcRequestPostProcessors.x509(
            CertificateReader.getCertificate(CertificateStringConstants.TEST_CERT_WITH_INVALID_UUID_IN_ORGANIZATION_UNIT)))
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"type\":\"password\",\"name\":\"" + credentialName + "\"}");

    final String expectedError = "The provided authentication mechanism does not "
        + "provide a valid identity. Please contact your system administrator.";

    mockMvc.perform(post)
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void dataEndpoint_withMutualTLS_deniesClientCertsWithOrgUnitNotPrefixedAccurately()
      throws Exception {
    setupDataEndpointMocks();

    final MockHttpServletRequestBuilder post = post(dataApiPath)
        .with(SecurityMockMvcRequestPostProcessors.x509(
            CertificateReader.getCertificate(CertificateStringConstants.TEST_CERT_WITH_INVALID_ORGANIZATION_UNIT_PREFIX)))
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"type\":\"password\",\"name\":\"" + credentialName + "\"}");

    final String expectedError = "The provided authentication mechanism does not provide a "
        + "valid identity. Please contact your system administrator.";

    mockMvc.perform(post)
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.error").value(expectedError));
  }

  @Test
  public void dataEndpoint_withMutualTLS_deniesClientCertsWithoutOrgUnit() throws Exception {
    setupDataEndpointMocks();

    final MockHttpServletRequestBuilder post = post(dataApiPath)
        .with(SecurityMockMvcRequestPostProcessors
            .x509(CertificateReader.getCertificate(CertificateStringConstants.TEST_CERT_WITHOUT_ORGANIZATION_UNIT)))
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"type\":\"password\",\"name\":\"" + credentialName + "\"}");

    final String expectedError = "The provided authentication mechanism does not provide a "
        + "valid identity. Please contact your system administrator.";

    mockMvc.perform(post)
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.error").value(expectedError));

  }

  @Test
  public void dataEndpoint_withMutualTLS_deniesClientCertsWithoutClientAuthExtension()
      throws Exception {
    setupDataEndpointMocks();

    final MockHttpServletRequestBuilder post = post(dataApiPath)
        .with(SecurityMockMvcRequestPostProcessors
            .x509(CertificateReader.getCertificate(CertificateStringConstants.SELF_SIGNED_CERT_WITH_NO_CLIENT_AUTH_EXT)))
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"type\":\"password\",\"name\":\"" + credentialName + "\"}");

    mockMvc.perform(post)
        .andDo(print())
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.error")
            .value(
                "The provided certificate is not authorized to be used for client authentication."));

  }

  @Test
  public void interpolateEndpoint_deniesAccessWithoutAuthentication() throws Exception {
    mockMvc.perform(post("/api/v1/interpolate")
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{}")
    ).andExpect(status().isUnauthorized());

  }

  @Test
  public void interpolateEndpoint_withAcceptedToken_allowsAccess() throws Exception {
    final MockHttpServletRequestBuilder post = post("/api/v1/interpolate")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(MediaType.APPLICATION_JSON)
        .contentType(MediaType.APPLICATION_JSON)
        .content("{}");

    mockMvc.perform(post)
        .andExpect(status().isOk());

  }

  private void setupDataEndpointMocks() {
    when(credentialVersionDataService.save(any(CredentialVersion.class))).thenAnswer(invocation -> {
      PasswordCredentialVersion passwordCredential = invocation
          .getArgumentAt(0, PasswordCredentialVersion.class);
      passwordCredential.setUuid(UUID.randomUUID());
      passwordCredential.setVersionCreatedAt(Instant.now());
      return passwordCredential;
    });
  }
}
