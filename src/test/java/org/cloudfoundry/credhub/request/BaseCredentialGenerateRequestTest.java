package org.cloudfoundry.credhub.request;

import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.helper.JsonTestHelper;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

@RunWith(JUnit4.class)
public class BaseCredentialGenerateRequestTest {

  @Test
  public void validate_whenTheRequestIsValid_doesNotHaveAnyConstraintValidations() {
    String json = "{"
        + "\"name\":\"some-name\","
        + "\"type\":\"password\","
        + "\"overwrite\":true"
        + "}";

    BaseCredentialGenerateRequest request = JsonTestHelper
        .deserialize(json, BaseCredentialGenerateRequest.class);
    request.validate();
  }

  @Test
  public void validate_whenTypeIsNotSet_throwsInvalidTypeWithGeneratePromptError() throws Exception {
    try {
      String json = "{"
          + "\"name\":\"some-name\","
          + "\"overwrite\":true"
          + "}";

      BaseCredentialGenerateRequest request = JsonTestHelper
          .deserialize(json, BaseCredentialGenerateRequest.class);
      request.validate();
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.invalid_type_with_generate_prompt"));
    }
  }

  @Test
  public void validate_whenBothOverwriteAndModeAreSet_throwsException() {
    try {
      String json = "{"
          + "\"name\":\"some-name\","
          + "\"type\":\"password\","
          + "\"overwrite\":true,"
          + "\"mode\":\"overwrite\""
          + "}";

      BaseCredentialGenerateRequest request = JsonTestHelper
          .deserialize(json, BaseCredentialGenerateRequest.class);
      request.validate();
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.overwrite_and_mode_both_provided"));
    }
  }

  @Test
  public void validate_whenTypeIsValue_throwsException() {
    try {
      String json = "{"
          + "\"name\":\"some-name\","
          + "\"type\":\"value\","
          + "\"overwrite\":true"
          + "}";

      BaseCredentialGenerateRequest request = JsonTestHelper
          .deserialize(json, BaseCredentialGenerateRequest.class);
      request.validate();
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.cannot_generate_type"));
    }
  }

  @Test
  public void validate_whenTypeIsJson_throwsException() {
    try {
      String json = "{"
          + "\"name\":\"some-name\","
          + "\"type\":\"json\","
          + "\"overwrite\":true"
          + "}";

      BaseCredentialGenerateRequest request = JsonTestHelper
          .deserialize(json, BaseCredentialGenerateRequest.class);
      request.validate();
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.cannot_generate_type"));
    }
  }

  @Test
  public void validate_whenTypeIsTotallyWrong_throwsException() {
    try {
      String json = "{"
          + "\"name\":\"some-name\","
          + "\"type\":\"banana\","
          + "\"overwrite\":true"
          + "}";

      BaseCredentialGenerateRequest request = JsonTestHelper
          .deserialize(json, BaseCredentialGenerateRequest.class);
      request.validate();
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.invalid_type_with_generate_prompt"));
    }
  }
}
