package org.cloudfoundry.credhub.integration;

import java.time.temporal.ChronoUnit;
import java.util.Calendar;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import com.jayway.jsonpath.JsonPath;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.helpers.RequestHelper;
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer;
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;
import org.junit.runner.RunWith;

import static org.cloudfoundry.credhub.helpers.RequestHelper.generateCertificateCredential;
import static org.cloudfoundry.credhub.helpers.RequestHelper.generatePassword;
import static org.cloudfoundry.credhub.helpers.RequestHelper.getCertificateCredentialsByName;
import static org.cloudfoundry.credhub.helpers.RequestHelper.getCredential;
import static org.cloudfoundry.credhub.utils.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
public class CredentialGetTest {

  private MockMvc mockMvc;

  private final String credentialName = "/my-namespace/subTree/credential-name";

  @Autowired
  private WebApplicationContext webApplicationContext;
  @Autowired
  private ApplicationContext applicationContext;
  @Autowired
  private ApplicationEventPublisher applicationEventPublisher;

  @Rule
  public Timeout globalTimeout = Timeout.seconds(60);

  @BeforeClass
  public static void beforeAll() {
    BouncyCastleFipsConfigurer.configure();
  }

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();
    applicationEventPublisher.publishEvent(new ContextRefreshedEvent(applicationContext));
  }

  @Test
  public void getCertificateCredentials_whenCurrentFalseReturnsAllCertificateCredentials() throws Exception {
    final String credentialName = "/first-certificate";

    generateCertificateCredential(mockMvc, credentialName, true, "test", null, ALL_PERMISSIONS_TOKEN);

    String response = getCertificateCredentialsByName(mockMvc, ALL_PERMISSIONS_TOKEN, credentialName);
    final String uuid = JsonPath.parse(response)
      .read("$.certificates[0].id");

    RequestHelper.regenerateCertificate(mockMvc, uuid, true, ALL_PERMISSIONS_TOKEN);
    RequestHelper.regenerateCertificate(mockMvc, uuid, false, ALL_PERMISSIONS_TOKEN);

    final MockHttpServletRequestBuilder request = get("/api/v1/data?name=" + credentialName + "&current=false")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    response = mockMvc.perform(request)
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    final JSONObject responseObject = new JSONObject(response);

    assertThat(responseObject.getJSONArray("data").length(), equalTo(3));
  }

  @Test
  public void getCredentialByName_shouldBeCaseInsensitive() throws Exception {
    generatePassword(mockMvc, credentialName, true, 20, ALL_PERMISSIONS_TOKEN);

    final String response = getCredential(mockMvc, credentialName.toUpperCase(), ALL_PERMISSIONS_TOKEN);
    assertThat(response, containsString(credentialName));
  }


  @Test
  public void getCertificateCredentials_whenCurrentTrueReturnsOnlyTransitionalAndLatest() throws Exception {
    final String credentialName = "/second-certificate";

    generateCertificateCredential(mockMvc, credentialName, true, "test", null, ALL_PERMISSIONS_TOKEN);

    String response = getCertificateCredentialsByName(mockMvc, ALL_PERMISSIONS_TOKEN, credentialName);
    final String uuid = JsonPath.parse(response)
      .read("$.certificates[0].id");

    final String transitionalCertificate = JsonPath.parse(RequestHelper.regenerateCertificate(mockMvc, uuid, true, ALL_PERMISSIONS_TOKEN))
      .read("$.value.certificate");

    final String nonTransitionalCertificate = JsonPath.parse(RequestHelper.regenerateCertificate(mockMvc, uuid, false, ALL_PERMISSIONS_TOKEN))
      .read("$.value.certificate");

    final MockHttpServletRequestBuilder request = get("/api/v1/data?name=" + credentialName + "&current=true")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    response = mockMvc.perform(request)
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    final JSONObject responseObject = new JSONObject(response);

    assertThat(responseObject.getJSONArray("data").length(), equalTo(2));
    final List<String> certificates = JsonPath.parse(response)
      .read("$.data[*].value.certificate");
    assertThat(certificates, containsInAnyOrder(transitionalCertificate, nonTransitionalCertificate));
  }

  @Test
  public void getCertificate_withNonNullExpiryDate_andExpectExpiryDate() throws Exception {

    final String credentialName = "/test-certificate";

    generateCertificateCredential(mockMvc, credentialName, true, "test", null, ALL_PERMISSIONS_TOKEN);


    final MockHttpServletRequestBuilder request = get("/api/v1/data?name=" + credentialName + "&current=true")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON);

    final String response = mockMvc.perform(request)
      .andExpect(status().isOk())
      .andReturn().getResponse().getContentAsString();

    final String expiryDate = JsonPath.parse(response).read("$.data[0].expiry_date");
    final String truncatedExpiryDate = expiryDate.substring(0, expiryDate.indexOf('T'));

    final Calendar calendar = Calendar.getInstance();
    calendar.add(Calendar.DATE, 365);
    final String expectedTime = calendar.getTime().toInstant().truncatedTo(ChronoUnit.SECONDS).toString();
    final String truncatedExpected = expectedTime.substring(0, expectedTime.indexOf('T'));
    assertThat(truncatedExpiryDate, equalTo(truncatedExpected));

  }
}
