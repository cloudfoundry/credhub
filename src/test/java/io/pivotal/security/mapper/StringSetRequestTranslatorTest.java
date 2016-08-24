package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedStringSecret;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

import javax.validation.ValidationException;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles("unit-test")
public class StringSetRequestTranslatorTest {

  @Autowired
  private Configuration jsonConfiguration;

  private StringSetRequestTranslator subject;

  private NamedStringSecret entity;

  {
    wireAndUnwire(this);

    describe("populating entity from JSON", () -> {

      beforeEach(() -> {
        subject = new StringSetRequestTranslator();
        entity = subject.makeEntity("rick");
      });

      it("fills in entity with values from JSON", () -> {
        String requestJson = "{\"type\":\"value\",\"value\":\"myValue\"}";

        DocumentContext parsed = JsonPath.using(jsonConfiguration).parse(requestJson);
        subject.populateEntityFromJson(entity, parsed);
        assertThat(entity.getValue(), equalTo("myValue"));
      });

      itThrowsWithMessage("exception when empty value is given", ValidationException.class, "error.missing_string_secret_value", () -> {
        String requestJson = "{\"type\":\"value\",\"value\":\"\"}";
        DocumentContext parsed = JsonPath.using(jsonConfiguration).parse(requestJson);
        subject.populateEntityFromJson(entity, parsed);
      });

      itThrowsWithMessage("exception when value is omitted", ValidationException.class, "error.missing_string_secret_value", () -> {
        String requestJson = "{\"type\":\"value\"}";
        DocumentContext parsed = JsonPath.using(jsonConfiguration).parse(requestJson);
        subject.populateEntityFromJson(entity, parsed);
      });
    });
  }
}