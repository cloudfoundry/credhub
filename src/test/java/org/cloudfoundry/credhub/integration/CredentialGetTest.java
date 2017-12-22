package org.cloudfoundry.credhub.integration;

import com.jayway.jsonpath.JsonPath;
import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.constants.CredentialWriteMode;
import org.cloudfoundry.credhub.helper.RequestHelper;
import org.cloudfoundry.credhub.util.AuthConstants;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.json.JSONObject;
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

import static org.cloudfoundry.credhub.helper.RequestHelper.generateCertificateCredential;
import static org.cloudfoundry.credhub.helper.RequestHelper.getCertificateCredentialsByName;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@TestPropertySource(properties = "security.authorization.acls.enabled=true")
@Transactional
public class CredentialGetTest {

  private MockMvc mockMvc;

  @Autowired
  private WebApplicationContext webApplicationContext;

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
  }

  @Test
  public void getCertificateCredentials_whenCurrentFalseReturnsAllCertificateCredentials() throws Exception {
    String credentialName = "/first-certificate";

    generateCertificateCredential(mockMvc, credentialName, CredentialWriteMode.OVERWRITE.mode, "test", null);

    String response = getCertificateCredentialsByName(mockMvc, UAA_OAUTH2_PASSWORD_GRANT_TOKEN, credentialName);
    String uuid = JsonPath.parse(response)
        .read("$.certificates[0].id");

    RequestHelper.regenerateCertificate(mockMvc, uuid, true);
    RequestHelper.regenerateCertificate(mockMvc, uuid, false);

    final MockHttpServletRequestBuilder request = get("/api/v1/data?name=" + credentialName + "&current=false")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON);

    response = mockMvc.perform(request)
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();

    JSONObject responseObject = new JSONObject(response);

    assertThat(responseObject.getJSONArray("data").length(), equalTo(3));
  }


  @Test
  public void getCertificateCredentials_whenCurrentTrueReturnsOnlyTransitionalAndLatest() throws Exception {
    String credentialName = "/second-certificate";

    generateCertificateCredential(mockMvc, credentialName, CredentialWriteMode.OVERWRITE.mode, "test", null);

    String response = getCertificateCredentialsByName(mockMvc, UAA_OAUTH2_PASSWORD_GRANT_TOKEN, credentialName);
    String uuid = JsonPath.parse(response)
        .read("$.certificates[0].id");

    String transitionalCertificate = JsonPath.parse(RequestHelper.regenerateCertificate(mockMvc, uuid, true))
        .read("$.value.certificate");

    String nonTransitionalCertificate = JsonPath.parse(RequestHelper.regenerateCertificate(mockMvc, uuid, false))
        .read("$.value.certificate");

    final MockHttpServletRequestBuilder request = get("/api/v1/data?name=" + credentialName + "&current=true")
        .header("Authorization", "Bearer " + AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON);

    response = mockMvc.perform(request)
        .andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString();

    JSONObject responseObject = new JSONObject(response);

    assertThat(responseObject.getJSONArray("data").length(), equalTo(2));
    List<String> certificates = JsonPath.parse(response)
        .read("$.data[*].value.certificate");
    assertThat(certificates, containsInAnyOrder(transitionalCertificate, nonTransitionalCertificate));
  }

}
