package io.pivotal.security.integration;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.util.DatabaseProfileResolver;
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

import static io.pivotal.security.helper.RequestHelper.generatePassword;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class CredentialGenerateTest {
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
  public void credentialCanBeOverwrittenWhenModeIsSetToOverwriteInRequest() throws Exception {
    String firstResponse = generatePassword(mockMvc, CREDENTIAL_NAME, "overwrite");
    String originalPassword = (new JSONObject(firstResponse)).getString("value");

    String secondResponse = generatePassword(mockMvc, CREDENTIAL_NAME, "overwrite");
    String updatedPassword = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalPassword, not(equalTo(updatedPassword)));
  }

  @Test
  public void credentialNotOverwrittenWhenModeIsSetToNotOverwriteInRequest() throws Exception {
    String firstResponse = generatePassword(mockMvc, CREDENTIAL_NAME, "overwrite");
    String originalPassword = (new JSONObject(firstResponse)).getString("value");

    String secondResponse = generatePassword(mockMvc, CREDENTIAL_NAME, "no-overwrite");
    String samePassword = (new JSONObject(secondResponse)).getString("value");

    assertThat(originalPassword, equalTo(samePassword));
  }

}
