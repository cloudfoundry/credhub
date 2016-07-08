package io.pivotal.security.mapper;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.view.CertificateAuthority;
import org.exparity.hamcrest.BeanMatchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.validation.ValidationException;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class CertificateAuthorityRequestTranslatorTest {
  @Autowired
  private Configuration jsonConfiguration;

  @Test
  public void doValidScenarios() {
    doTestValid(new CertificateAuthority("root", "a", "b"), "a", "b");
  }

  @Test
  public void doInvalidScenarios() throws ValidationException {
    doTestInvalid("root", "", "a", "error.missing_ca_credentials");
    doTestInvalid("root", "b", "", "error.missing_ca_credentials");
    doTestInvalid("root", "", "", "error.missing_ca_credentials");
    doTestInvalid("root", "", "a", "error.missing_ca_credentials");
    doTestInvalid("root", "b", "", "error.missing_ca_credentials");
    doTestInvalid("invalid_ca_type", "b", "a", "error.type_invalid");
  }

  private void doTestValid(CertificateAuthority expected, String pub, String priv) {
    String requestJson = "{\"type\":\"root\",\"root\":{\"public\":\"" + pub + "\",\"private\":\"" + priv + "\"}}";

    DocumentContext parsed = JsonPath.using(jsonConfiguration).parse(requestJson);
    CertificateAuthority actual = new CertificateAuthorityRequestTranslator().createAuthorityFromJson(parsed);
    assertThat(actual, BeanMatchers.theSameAs(expected));
  }

  private void doTestInvalid(String type, String pub, String priv, String expectedErrorMessage) throws ValidationException {
    String requestJson = "{\"type\":" + type + ",\"root\":{\"public\":\"" + pub + "\",\"private\":\"" + priv + "\"}}";

    DocumentContext parsed = JsonPath.using(jsonConfiguration).parse(requestJson);
    try {
      new CertificateAuthorityRequestTranslator().createAuthorityFromJson(parsed);
      fail();
    } catch (ValidationException ve) {
      assertThat(ve.getMessage(), equalTo(expectedErrorMessage));
    }
  }
}