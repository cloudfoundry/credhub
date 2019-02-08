package org.cloudfoundry.credhub.integration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import org.cloudfoundry.credhub.AuthConstants;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.helpers.RequestHelper;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_TOKEN;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

@RunWith(SpringRunner.class)
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
    RequestHelper.generateCa(mockMvc, CA_NAME, AuthConstants.NO_PERMISSIONS_TOKEN);
    //This request uses the PASSWORD GRANT TOKEN under the hood and hence should fail if permissions are enforced.
    final String firstResponse = RequestHelper
      .generateCertificateCredential(mockMvc, CREDENTIAL_NAME, false, "some-common-name", CA_NAME, ALL_PERMISSIONS_TOKEN);
    assertThat(firstResponse, containsString(CREDENTIAL_NAME));
  }

}
