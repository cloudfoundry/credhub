package org.cloudfoundry.credhub.integration;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.constants.CredentialWriteMode;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import static org.cloudfoundry.credhub.helper.RequestHelper.generateRsa;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class RsaGenerateTest {
  private static final String CREDENTIAL_NAME = "/set_credential";

  @Autowired
  private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;

  @Before
  public void setup() {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();
  }

  @Test
  public void credentialNotOverwrittenWhenModeIsSetToConvergeAndParametersAreTheSame() throws Exception {
    String firstResponse = generateRsa(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.CONVERGE.mode, 2048);
    String originalPassword = (new JSONObject(firstResponse)).getString("value");

    String secondResponse = generateRsa(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.CONVERGE.mode, 2048);
    String samePassword = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalPassword, equalTo(samePassword));
  }

  @Test
  public void credentialNotOverwrittenWhenModeIsSetToConvergeAndParametersAreTheSameAndAreTheDefault() throws Exception {
    String firstResponse = generateRsa(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.OVERWRITE.mode, null);
    String originalPassword = (new JSONObject(firstResponse)).getString("value");

    String secondResponse = generateRsa(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.CONVERGE.mode, null);
    String samePassword = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalPassword, equalTo(samePassword));
  }

  @Test
  public void credentialOverwrittenWhenModeIsSetToConvergeAndParametersNotTheSame() throws Exception {
    String firstResponse = generateRsa(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.OVERWRITE.mode, 4096);
    String originalPassword = (new JSONObject(firstResponse)).getString("value");

    String secondResponse = generateRsa(mockMvc, CREDENTIAL_NAME, CredentialWriteMode.CONVERGE.mode, 2048);
    String updatedPassword = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalPassword, not(equalTo(updatedPassword)));
  }
}
