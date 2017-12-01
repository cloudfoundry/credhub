package io.pivotal.security.integration;


import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.helper.AuditingHelper;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_FIND;
import static io.pivotal.security.helper.RequestHelper.generateCa;
import static io.pivotal.security.helper.RequestHelper.generateCertificateCredential;
import static io.pivotal.security.helper.RequestHelper.generatePassword;
import static io.pivotal.security.helper.RequestHelper.getCertificateCredentials;
import static io.pivotal.security.helper.RequestHelper.getCertificateCredentialsByName;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@TestPropertySource(properties = "security.authorization.acls.enabled=true")
@Transactional
public class CertificateGetTest {
  @Autowired
  private WebApplicationContext webApplicationContext;

  @Autowired
  private RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  private EventAuditRecordRepository eventAuditRecordRepository;

  private MockMvc mockMvc;

  private AuditingHelper auditingHelper;

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();

    auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);
  }

  @Test
  public void getCertificateCredentials_returnsAllCertificateCredentials() throws Exception {
    generateCertificateCredential(mockMvc, "/first-certificate", "overwrite", "test", null);
    generateCertificateCredential(mockMvc, "/second-certificate", "overwrite", "first-version", null);
    generateCertificateCredential(mockMvc, "/second-certificate", "overwrite", "second-version", null);
    generatePassword(mockMvc, "invalid-cert", "overwrite", null);
    String response = getCertificateCredentials(mockMvc);

    List<String> names = JsonPath.parse(response)
        .read("$.certificates[*].name");

    assertThat(names, hasSize(2));
    assertThat(names, containsInAnyOrder("/first-certificate", "/second-certificate"));
    assertThat(names, not(containsInAnyOrder("/invalid-cert")));

    auditingHelper.verifyAuditing(CREDENTIAL_FIND, null, UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, "/api/v1/certificates", 200);
  }

  @Test
  public void getCertificateCredentials_returnsOnlyCertificatesTheUserCanAccess() throws Exception {
    generateCa(mockMvc, "my-certificate", UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    generateCa(mockMvc, "your-certificate", UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN);

    String response = getCertificateCredentials(mockMvc, UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    List<String> names = JsonPath.parse(response)
        .read("$.certificates[*].name");

    assertThat(names, hasSize(1));
    assertThat(names, containsInAnyOrder("/my-certificate"));
    assertThat(names, not(containsInAnyOrder("/your-certificate")));

    response = getCertificateCredentials(mockMvc, UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN);
    names = JsonPath.parse(response)
        .read("$.certificates[*].name");

    assertThat(names, hasSize(1));
    assertThat(names, not(containsInAnyOrder("/my-certificate")));
    assertThat(names, containsInAnyOrder("/your-certificate"));
  }

  @Test
  public void getCertificateCredentials_withNameProvided_returnsACertificateWithThatName() throws Exception {
    generateCa(mockMvc, "my-certificate", UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    generateCa(mockMvc, "also-my-certificate", UAA_OAUTH2_PASSWORD_GRANT_TOKEN);

    String response = getCertificateCredentialsByName(mockMvc, UAA_OAUTH2_PASSWORD_GRANT_TOKEN, "my-certificate");
    List<String> names = JsonPath.parse(response)
        .read("$.certificates[*].name");

    assertThat(names, hasSize(1));
    assertThat(names, containsInAnyOrder("/my-certificate"));
    auditingHelper.verifyAuditing(CREDENTIAL_FIND, "/my-certificate", UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, "/api/v1/certificates", 200);
  }

  @Test
  public void getCertificateCredentials_whenNameDoesNotMatchACredential_returns404WithMessage() throws Exception {
    MockHttpServletRequestBuilder get = get("/api/v1/certificates?name=" + "some-other-certificate")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON);

    String response = mockMvc.perform(get)
        .andDo(print())
        .andExpect(status().isNotFound())
        .andReturn().getResponse().getContentAsString();

    assertThat(response, containsString("The request could not be completed because the credential does not exist or you do not have sufficient authorization."));
    auditingHelper.verifyAuditing(CREDENTIAL_FIND, "/some-other-certificate", UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, "/api/v1/certificates", 404);
  }

  @Test
  public void getCertificateCredentialsByName_doesNotReturnOtherCredentialTypes() throws Exception {
    generatePassword(mockMvc, "my-credential", "overwrite", 10);

    MockHttpServletRequestBuilder get = get("/api/v1/certificates?name=" + "my-credential")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON);

    String response = mockMvc.perform(get)
        .andDo(print())
        .andExpect(status().isNotFound())
        .andReturn().getResponse().getContentAsString();

    assertThat(response, containsString("The request could not be completed because the credential does not exist or you do not have sufficient authorization."));
    auditingHelper.verifyAuditing(CREDENTIAL_FIND, "/my-credential", UAA_OAUTH2_PASSWORD_GRANT_ACTOR_ID, "/api/v1/certificates", 404);
  }

  @Test
  public void getCertificateCredentials_whenNameIsProvided_andUserDoesNotHaveRequiredPermissions_returns404WithMessage() throws Exception {
    generateCa(mockMvc, "my-certificate", UAA_OAUTH2_PASSWORD_GRANT_TOKEN);

    MockHttpServletRequestBuilder get = get("/api/v1/certificates?name=" + "my-certificate")
        .header("Authorization", "Bearer " + UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON);

    String response = mockMvc.perform(get)
        .andDo(print())
        .andExpect(status().isNotFound())
        .andReturn().getResponse().getContentAsString();

    assertThat(response, containsString("The request could not be completed because the credential does not exist or you do not have sufficient authorization."));
    auditingHelper.verifyAuditing(CREDENTIAL_FIND, "/my-certificate", UAA_OAUTH2_CLIENT_CREDENTIALS_ACTOR_ID, "/api/v1/certificates", 404);
  }
}
