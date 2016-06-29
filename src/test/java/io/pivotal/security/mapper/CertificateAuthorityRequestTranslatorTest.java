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

import static org.junit.Assert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class CertificateAuthorityRequestTranslatorTest {
  @Autowired
  private Configuration jsonConfiguration;

  @Test
  public void doValidScenarios() {
    doTest(new CertificateAuthority(null, "a"), "", "a");
    doTest(new CertificateAuthority("b", null), "b", "");
    doTest(new CertificateAuthority(null, null), "", "");
    doTest(new CertificateAuthority(null, "a"),  "", "a");
    doTest(new CertificateAuthority("b", null),  "b", "");
  }

  private void doTest(CertificateAuthority expected, String pub, String priv) {
    String requestJson = "{\"root\":{\"public\":\"" + pub + "\",\"private\":\"" + priv + "\"}}";

    DocumentContext parsed = JsonPath.using(jsonConfiguration).parse(requestJson);
    CertificateAuthority actual = new CertificateAuthorityRequestTranslator().createAuthorityFromJson(parsed);
    assertThat(actual, BeanMatchers.theSameAs(expected));
  }
}