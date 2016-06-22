package io.pivotal.security.mapper;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.model.CertificateSecret;
import org.exparity.hamcrest.BeanMatchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.validation.ValidationException;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.*;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
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

  private void doTest(CertificateSecret expected, String ca, String pub, String priv) {
    String requestJson = "{\"type\":\"certificate\",\"certificate\":{\"ca\":\"" + ca + "\",\"public\":\"" + pub + "\",\"private\":\"" + priv + "\"}}";

    DocumentContext parsed = JsonPath.using(jsonConfiguration).parse(requestJson);
    CertificateSecret actual = new CertificateSetRequestTranslator().createSecretFromJson(parsed);
    assertThat(actual, BeanMatchers.theSameAs(expected));
  }
}