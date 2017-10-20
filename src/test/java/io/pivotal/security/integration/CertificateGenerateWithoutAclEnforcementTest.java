package io.pivotal.security.integration;

import io.pivotal.security.CredentialManagerApp;
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
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import static io.pivotal.security.helper.RequestHelper.generateCa;
import static io.pivotal.security.helper.RequestHelper.generateCertificateCredential;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@TestPropertySource(properties = "security.authorization.acls.enabled=false")
@Transactional
public class CertificateGenerateWithoutAclEnforcementTest {

  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;
  private static final String CREDENTIAL_NAME = "some-certificate";
  private static final String CA_NAME = "some-ca";

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
  }

  @Test
  public void certificateGeneration_whenPermissionsAreNotEnforced_WithValidCa_generatesTheCertificate()
      throws Exception {
    generateCa(mockMvc, CA_NAME, UAA_OAUTH2_CLIENT_CREDENTIALS_TOKEN);
    //This request uses the PASSWORD GRANT TOKEN under the hood and hence should fail if permissions are enforced.
    String firstResponse = generateCertificateCredential(mockMvc, CREDENTIAL_NAME, "converge", "some-common-name", CA_NAME);
    assertThat(firstResponse, containsString(CREDENTIAL_NAME));
  }

}
