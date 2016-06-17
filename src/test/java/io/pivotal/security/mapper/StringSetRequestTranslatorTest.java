package io.pivotal.security.mapper;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.model.StringSecret;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.validation.ValidationException;

import static io.pivotal.security.matcher.ReflectiveEqualsMatcher.reflectiveEqualTo;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.*;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class StringSetRequestTranslatorTest {

  @Autowired
  private Configuration jsonConfiguration;

  @Test
  public void ensureStringSecretIsSetWhenValidValueGiven() {
    String requestJson = "{\"type\":\"value\",\"value\":\"myValue\"}";

    doTest(new StringSecret("myValue"), requestJson);
  }

  @Test
  public void ensureStringSecretIsSetWhenEmptyValueGiven() {
    String requestJson = "{\"type\":\"value\",\"value\":\"\"}";
    try {
      doTest(null, requestJson);
    } catch (ValidationException e) {
      assertThat(e.getMessage(), equalTo("error.missing_string_secret_value"));
      return;
    }
    fail();
  }

  @Test
  public void ensureStringSecretIsSetWhenValueOmitted() {
    String requestJson = "{\"type\":\"value\"}";
    try {
      doTest(null, requestJson);
    } catch (ValidationException e) {
      assertThat(e.getMessage(), equalTo("error.missing_string_secret_value"));
      return;
    }
    fail();
  }

  private void doTest(StringSecret expected, String requestJson) {
    DocumentContext parsed = JsonPath.using(jsonConfiguration).parse(requestJson);
    StringSecret actual = new StringSetRequestTranslator().createSecretFromJson(parsed);
    assertThat(actual, reflectiveEqualTo(expected));
  }
}