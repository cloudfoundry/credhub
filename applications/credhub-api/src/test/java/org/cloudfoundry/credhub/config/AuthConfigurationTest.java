package org.cloudfoundry.credhub.config;

import java.time.Instant;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.cloudfoundry.credhub.AuthConstants;
import org.cloudfoundry.credhub.CertificateStringConstants;
import org.cloudfoundry.credhub.CredHubApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.services.DefaultCredentialVersionDataService;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.utils.CertificateReader;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredHubApp.class)
@Transactional
@SuppressFBWarnings(
  value = "SS_SHOULD_BE_STATIC",
  justification = "Test files generally don't need static fields."
)
public class AuthConfigurationTest {

  private final String dataApiPath = "/api/v1/data";
  private final String credentialName = "test";

  @Autowired
  private WebApplicationContext applicationContext;

  @MockBean
  private DefaultCredentialVersionDataService credentialVersionDataService;

  private MockMvc mockMvc;

  @Before
  public void beforeEach() {
    mockMvc = MockMvcBuilders
      .webAppContextSetup(applicationContext)
      .apply(springSecurity())
      .build();
  }

  @Test
  public void infoCanBeAccessedWithoutAuthentication() throws Exception {
    mockMvc.perform(get("/info").accept(MediaType.APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(jsonPath("$.auth-server.url").isNotEmpty());
  }

  @Test
  public void healthCanBeAccessWithoutAuthentication() throws Exception {
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
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
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

    final CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.SELF_SIGNED_CERT_WITH_CLIENT_AUTH_EXT);

    final MockHttpServletRequestBuilder post = post(dataApiPath)
      .with(SecurityMockMvcRequestPostProcessors
        .x509(certificateReader.getCertificate()))
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
  public void dataEndpoint_withMutualTLS_deniesClientCertsWithOrgUnitsThatDontContainV4UUID()
    throws Exception {
    setupDataEndpointMocks();

    final CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.TEST_CERT_WITH_INVALID_UUID_IN_ORGANIZATION_UNIT);

    final MockHttpServletRequestBuilder post = post(dataApiPath)
      .with(SecurityMockMvcRequestPostProcessors.x509(
        certificateReader.getCertificate()))
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

    final CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.TEST_CERT_WITH_INVALID_ORGANIZATION_UNIT_PREFIX);

    final MockHttpServletRequestBuilder post = post(dataApiPath)
      .with(SecurityMockMvcRequestPostProcessors.x509(
        certificateReader.getCertificate()))
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

    final CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.TEST_CERT_WITHOUT_ORGANIZATION_UNIT);

    final MockHttpServletRequestBuilder post = post(dataApiPath)
      .with(SecurityMockMvcRequestPostProcessors
        .x509(certificateReader.getCertificate()))
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

    final CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.SELF_SIGNED_CERT_WITH_NO_CLIENT_AUTH_EXT);

    final MockHttpServletRequestBuilder post = post(dataApiPath)
      .with(SecurityMockMvcRequestPostProcessors
        .x509(certificateReader.getCertificate()))
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
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(MediaType.APPLICATION_JSON)
      .contentType(MediaType.APPLICATION_JSON)
      .content("{}");

    mockMvc.perform(post)
      .andExpect(status().isOk());

  }

  private void setupDataEndpointMocks() {
    when(credentialVersionDataService.save(any(CredentialVersion.class))).thenAnswer(invocation -> {
      final PasswordCredentialVersion passwordCredential = invocation.getArgument(0);
      passwordCredential.setUuid(UUID.randomUUID());
      passwordCredential.setVersionCreatedAt(Instant.now());
      return passwordCredential;
    });
  }
}
