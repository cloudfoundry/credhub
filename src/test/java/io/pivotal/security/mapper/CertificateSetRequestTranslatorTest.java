package io.pivotal.security.mapper;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.view.CertificateSecret;
import org.exparity.hamcrest.BeanMatchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import javax.validation.ValidationException;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles("unit-test")
public class CertificateSetRequestTranslatorTest {

  @Autowired
  private Configuration jsonConfiguration;

  @Test
  public void doValidScenarios() {
    doTest(new CertificateSecret(null, null, "a"), "", "", "a");
    doTest(new CertificateSecret(null, "b", null), "", "b", "");
    doTest(new CertificateSecret(null, "b", "a"), "", "b", "a");
    doTest(new CertificateSecret("c", null, null), "c", "", "");
    doTest(new CertificateSecret("c", null, "a"), "c", "", "a");
    doTest(new CertificateSecret("c", "b", null), "c", "b", "");
    doTest(new CertificateSecret("c", "b", "a"), "c", "b", "a");
  }

  @Test
  public void doInvalidScenario() {
    try {
      doTest(null, "", "", "");
    } catch (ValidationException e) {
      assertThat(e.getMessage(), equalTo("error.missing_certificate_credentials"));
      return;
    }
    fail();
  }

  private void doTest(CertificateSecret expected, String root, String certificate, String privateKey) {
    String requestJson = "{\"type\":\"certificate\",\"value\":{\"root\":\"" + root + "\",\"certificate\":\"" + certificate + "\",\"private\":\"" + privateKey + "\"}}";

    DocumentContext parsed = JsonPath.using(jsonConfiguration).parse(requestJson);
    CertificateSecret actual = new CertificateSetRequestTranslator().createSecretFromJson(parsed);
    assertThat(actual, BeanMatchers.theSameAs(expected));
  }
}