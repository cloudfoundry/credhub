package org.cloudfoundry.credhub.integration;


import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import com.jayway.jsonpath.JsonPath;
import org.cloudfoundry.credhub.AuthConstants;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.helpers.RequestHelper;
import org.json.JSONArray;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.AuthConstants.NO_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_TOKEN;
import static org.cloudfoundry.credhub.AuthConstants.USER_B_TOKEN;
import static org.cloudfoundry.credhub.helpers.RequestHelper.generateCa;
import static org.cloudfoundry.credhub.helpers.RequestHelper.generateCertificateCredential;
import static org.cloudfoundry.credhub.helpers.RequestHelper.generatePassword;
import static org.cloudfoundry.credhub.helpers.RequestHelper.getCertificateCredentials;
import static org.cloudfoundry.credhub.helpers.RequestHelper.getCertificateCredentialsByName;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test,unit-test-permissions", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
@Transactional
public class CertificateGetTest {

  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();
  }

  @Test
  public void getCertificateCredentials_returnsAllCertificateCredentials() throws Exception {
    generateCertificateCredential(mockMvc, "/user-a/first-certificate", true, "test", null, USER_A_TOKEN);
    generateCertificateCredential(mockMvc, "/user-a/second-certificate", true, "first-version",
      null, USER_A_TOKEN);
    generateCertificateCredential(mockMvc, "/user-a/second-certificate", true, "second-version",
      null, USER_A_TOKEN);
    generatePassword(mockMvc, "/user-a/invalid-cert", true, null, USER_A_TOKEN);
    final String response = getCertificateCredentials(mockMvc, USER_A_TOKEN);

    final List<String> names = JsonPath.parse(response).read("$.certificates[*].name");

    assertThat(names.size(), greaterThanOrEqualTo(2));
    assertThat(names, hasItems("/user-a/first-certificate", "/user-a/second-certificate"));
    assertThat(names, not(hasItems("/user-a/invalid-cert")));
  }

  @Test
  public void getCertificateCredentials_returnsOnlyCertificatesTheUserCanAccess() throws Exception {
    generateCa(mockMvc, "/user-a/certificate", USER_A_TOKEN);
    generateCa(mockMvc, "/user-b/certificate", USER_B_TOKEN);
    generateCa(mockMvc, "/shared-read-only/certificate", ALL_PERMISSIONS_TOKEN);

    String response = getCertificateCredentials(mockMvc, USER_A_TOKEN);
    List<String> names = JsonPath.parse(response)
      .read("$.certificates[*].name");

    assertThat(names.size(), greaterThanOrEqualTo(2));
    assertThat(names, hasItems("/user-a/certificate", "/shared-read-only/certificate"));
    assertThat(names, not(hasItems("/user-b/certificate")));

    response = getCertificateCredentials(mockMvc, USER_B_TOKEN);
    names = JsonPath.parse(response)
      .read("$.certificates[*].name");

    assertThat(names.size(), greaterThanOrEqualTo(2));
    assertThat(names, hasItems("/user-b/certificate", "/shared-read-only/certificate"));
    assertThat(names, not(hasItems("/user-a/certificate")));
  }

  @Test
  public void getCertificateCredentials_withNameProvided_returnsACertificateWithThatName() throws Exception {
    generateCa(mockMvc, "my-certificate", ALL_PERMISSIONS_TOKEN);
    generateCa(mockMvc, "also-my-certificate", ALL_PERMISSIONS_TOKEN);

    final String response = getCertificateCredentialsByName(mockMvc, ALL_PERMISSIONS_TOKEN, "my-certificate");
    final List<String> names = JsonPath.parse(response)
      .read("$.certificates[*].name");

    assertThat(names, hasSize(1));
    assertThat(names, containsInAnyOrder("/my-certificate"));
  }

  @Test
  public void getCertificateCredentials_whenNameDoesNotMatchACredential_returns404WithMessage() throws Exception {
    final MockHttpServletRequestBuilder get = get("/api/v1/certificates?name=" + "some-other-certificate")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON);

    final String response = mockMvc.perform(get)
      .andDo(print())
      .andExpect(status().isNotFound())
      .andReturn().getResponse().getContentAsString();

    assertThat(response, containsString(
      "The request could not be completed because the credential does not exist or you do not have sufficient authorization."));
  }

  @Test
  public void getCertificateCredentialsByName_doesNotReturnOtherCredentialTypes() throws Exception {
    generatePassword(mockMvc, "my-credential", true, 10, ALL_PERMISSIONS_TOKEN);

    final MockHttpServletRequestBuilder get = get("/api/v1/certificates?name=" + "my-credential")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON);

    final String response = mockMvc.perform(get)
      .andDo(print())
      .andExpect(status().isNotFound())
      .andReturn().getResponse().getContentAsString();

    assertThat(response, containsString(
      "The request could not be completed because the credential does not exist or you do not have sufficient authorization."));
  }

  @Test
  public void getCertificateCredentials_whenNameIsProvided_andUserDoesNotHaveRequiredPermissions_returns404WithMessage()
    throws Exception {
    generateCa(mockMvc, "my-certificate", ALL_PERMISSIONS_TOKEN);

    final MockHttpServletRequestBuilder get = get("/api/v1/certificates?name=" + "my-certificate")
      .header("Authorization", "Bearer " + NO_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON);

    final String response = mockMvc.perform(get)
      .andDo(print())
      .andExpect(status().isNotFound())
      .andReturn().getResponse().getContentAsString();

    assertThat(response, containsString(
      "The request could not be completed because the credential does not exist or you do not have sufficient authorization."));
  }

  @Test
  public void getCertificateVersionsByCredentialId_returnsAllVersionsOfTheCertificateCredential() throws Exception {
    final String firstResponse = generateCertificateCredential(mockMvc, "/first-certificate",
      true, "test", null, ALL_PERMISSIONS_TOKEN);
    final String secondResponse = generateCertificateCredential(mockMvc, "/first-certificate",
      true, "test", null, ALL_PERMISSIONS_TOKEN);

    final String firstVersion = JsonPath.parse(firstResponse).read("$.id");
    final String secondVersion = JsonPath.parse(secondResponse).read("$.id");

    final String response = getCertificateCredentialsByName(mockMvc, ALL_PERMISSIONS_TOKEN, "/first-certificate");

    final String certificateId = JsonPath.parse(response).read("$.certificates[0].id");

    final MockHttpServletRequestBuilder getVersions = get("/api/v1/certificates/" + certificateId + "/versions")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON);

    final String responseVersion = mockMvc.perform(getVersions)
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    final List<Map<String, String>> certificates = JsonPath.parse(responseVersion).read("$");

    assertThat(certificates, hasSize(2));
    assertThat(certificates.get(0).get("id"), containsString(secondVersion));
    assertThat(certificates.get(1).get("id"), containsString(firstVersion));
  }

  @Test
  public void getCertificateVersionsByCredentialId_withCurrentTrue_returnsCurrentVersionsOfTheCertificateCredential()
    throws Exception {
    final String credentialName = "/test-certificate";
    generateCertificateCredential(mockMvc, credentialName, true, "test", null, ALL_PERMISSIONS_TOKEN);

    String response = getCertificateCredentialsByName(mockMvc, ALL_PERMISSIONS_TOKEN, credentialName);
    final String uuid = JsonPath.parse(response)
      .read("$.certificates[0].id");

    final String transitionalCertificate = JsonPath.parse(RequestHelper.regenerateCertificate(mockMvc, uuid, true, ALL_PERMISSIONS_TOKEN))
      .read("$.value.certificate");

    final String nonTransitionalCertificate = JsonPath.parse(RequestHelper.regenerateCertificate(mockMvc, uuid, false, ALL_PERMISSIONS_TOKEN))
      .read("$.value.certificate");

    final MockHttpServletRequestBuilder request = get("/api/v1/certificates/" + uuid + "/versions?current=true")
      .header("Authorization", "Bearer " + AuthConstants.ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    response = mockMvc.perform(request)
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    final JSONArray jsonArray = new JSONArray(response);

    assertThat(jsonArray.length(), equalTo(2));
    final List<String> certificates = JsonPath.parse(response)
      .read("$[*].value.certificate");
    assertThat(certificates, containsInAnyOrder(transitionalCertificate, nonTransitionalCertificate));
  }

  @Test
  public void getCertificateVersionsByCredentialId_returnsError_whenUUIDIsInvalid() throws Exception {

    final MockHttpServletRequestBuilder get = get("/api/v1/certificates/" + "fake-uuid" + "/versions")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON);

    final String response = mockMvc.perform(get)
      .andDo(print())
      .andExpect(status().is4xxClientError())
      .andReturn().getResponse().getContentAsString();

    assertThat(response, containsString(
      "The request could not be completed because the credential does not exist or you do not have sufficient authorization."));
  }
}
