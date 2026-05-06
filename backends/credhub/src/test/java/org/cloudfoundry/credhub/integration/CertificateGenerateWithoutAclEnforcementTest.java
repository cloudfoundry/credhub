package org.cloudfoundry.credhub.integration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.helpers.RequestHelper;
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer;
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.cloudfoundry.credhub.utils.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.cloudfoundry.credhub.utils.AuthConstants.NO_PERMISSIONS_TOKEN;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

@ExtendWith(SpringExtension.class)
@Timeout(60)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
@TestPropertySource(properties = "security.authorization.acls.enabled=false")
@Transactional
public class CertificateGenerateWithoutAclEnforcementTest {

  private static final String CREDENTIAL_NAME = "some-certificate";
  private static final String CA_NAME = "some-ca";
  @Autowired
  private WebApplicationContext webApplicationContext;
  private MockMvc mockMvc;


  @BeforeAll
  public static void beforeAll() {
    BouncyCastleFipsConfigurer.configure();
  }

  @BeforeEach
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();
  }

  @Test
  public void certificateGeneration_whenPermissionsAreNotEnforced_WithValidCa_generatesTheCertificate()
    throws Exception {
    RequestHelper.generateCa(mockMvc, CA_NAME, NO_PERMISSIONS_TOKEN);
    //This request uses the PASSWORD GRANT TOKEN under the hood and hence should fail if permissions are enforced.
    final String firstResponse = RequestHelper
      .generateCertificateCredential(mockMvc, CREDENTIAL_NAME, false, "some-common-name", CA_NAME, ALL_PERMISSIONS_TOKEN);
    assertThat(firstResponse, containsString(CREDENTIAL_NAME));
  }

}
