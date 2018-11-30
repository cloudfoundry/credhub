package org.cloudfoundry.credhub.request;

import java.io.IOException;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import org.cloudfoundry.credhub.helper.JsonTestHelper;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.cloudfoundry.credhub.helper.JsonTestHelper.deserializeChecked;

@RunWith(JUnit4.class)
public class BaseCredentialSetRequestTest {
  @Test(expected = JsonMappingException.class)
  public void whenTypeIsNotSet_throwsException() throws IOException {
    String json = "{" +
      "\"name\":\"some-name\"," +
      "\"value\":\"some-value\"," +
      "\"overwrite\":true" +
      "}";

    JsonTestHelper.deserializeChecked(json, BaseCredentialSetRequest.class);
  }


  @Test(expected = InvalidTypeIdException.class)
  public void whenTypeIsEmptyString_throwsException() throws IOException {
    String json = "{" +
      "\"name\":\"some-name\"," +
      "\"type\":\"\"," +
      "\"value\":\"some-value\"," +
      "\"overwrite\":true" +
      "}";

    JsonTestHelper.deserializeChecked(json, BaseCredentialSetRequest.class);
  }

  @Test(expected = InvalidTypeIdException.class)
  public void whenTypeIsUnknown_throwsException() throws IOException {
    String json = "{" +
      "\"name\":\"some-name\"," +
      "\"type\":\"moose\"," +
      "\"value\":\"some-value\"," +
      "\"overwrite\":true" +
      "}";

    JsonTestHelper.deserializeChecked(json, BaseCredentialSetRequest.class);
  }

  @Test(expected = UnrecognizedPropertyException.class)
  public void whenValueHasUnknownField_throwsException() throws IOException {
    String json = "{\n"
      + "  \"name\": \"/example/certificate\",\n"
      + "  \"type\": \"certificate\",\n"
      + "  \"value\": {"
      + "    \"foo\": \"\""
      + "  }"
      + "}";
    deserializeChecked(json, BaseCredentialSetRequest.class);
  }
}
