package io.pivotal.security.request;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.helper.JsonHelper;
import org.junit.runner.RunWith;

import java.util.Arrays;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.deserializeChecked;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.request.AccessControlOperation.READ;
import static io.pivotal.security.request.AccessControlOperation.WRITE;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

@RunWith(Spectrum.class)
public class BaseSecretSetRequestTest {

  {
    describe("when type is not set", () -> {
      itThrows("should throw an JsonMappingException", JsonMappingException.class, () -> {
        String json = "{" +
            "\"name\":\"some-name\"," +
            "\"value\":\"some-value\"," +
            "\"overwrite\":true" +
            "}";

        JsonHelper.deserializeChecked(json, BaseSecretSetRequest.class);
      });
    });

    describe("when type is an empty string", () -> {
      itThrows("should throw an InvalidTypeIdException", InvalidTypeIdException.class, () -> {
        String json = "{" +
            "\"name\":\"some-name\"," +
            "\"type\":\"\"," +
            "\"value\":\"some-value\"," +
            "\"overwrite\":true" +
            "}";

        JsonHelper.deserializeChecked(json, BaseSecretSetRequest.class);
      });
    });

    describe("when type is unknown", () -> {
      itThrows("should throw an InvalidTypeIdException", InvalidTypeIdException.class, () -> {
        String json = "{" +
            "\"name\":\"some-name\"," +
            "\"type\":\"moose\"," +
            "\"value\":\"some-value\"," +
            "\"overwrite\":true" +
            "}";

        JsonHelper.deserializeChecked(json, BaseSecretSetRequest.class);
      });
    });

    describe("when value has an unknown field", () -> {
      itThrows("should be invalid", UnrecognizedPropertyException.class, () -> {
        String json = "{\n"
            + "  \"name\": \"/example/certificate\",\n"
            + "  \"type\": \"certificate\",\n"
            + "  \"value\": {"
            + "    \"foo\": \"\""
            + "  }"
            + "}";
        deserializeChecked(json,
            BaseSecretSetRequest.class);
      });
    });

    describe("#addCurrentUser", () -> {
      describe("when there are no access contol entries in the request", () -> {
        it("should add access control entry for the current user", () -> {
          // language=JSON
          String json = "{\n" +
              "\"name\":\"some-name\"," +
              "\"type\":\"password\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true" +
              "}";
          BaseSecretSetRequest setRequest = JsonHelper.deserialize(json, BaseSecretSetRequest.class);
          AccessControlEntry expectedEntry = new AccessControlEntry("my-actor", Arrays.asList(READ, WRITE));
          setRequest.addCurrentUser(expectedEntry);
          assertThat(setRequest.getAccessControlEntries(), equalTo(Arrays.asList(expectedEntry)));
        });
      });

      describe("when there are access control entries in the request", () -> {
        it("should add access control entry for the current user", () -> {
          // language=JSON
          String json = "{\n" +
              "\"name\":\"some-name\"," +
              "\"type\":\"password\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true, \n" +
              "\"access_control_entries\": [{\n" +
              "  \"actor\": \"my-other-actor\",\n" +
              "  \"operations\": [\"read\"]\n" +
              "}]\n" +
              "}";
          BaseSecretSetRequest setRequest = JsonHelper.deserialize(json, BaseSecretSetRequest.class);
          AccessControlEntry currentUserAccessControlEntry =
              new AccessControlEntry("my-actor", Arrays.asList(READ, WRITE));
          AccessControlEntry passedAccessControlEntry =
              new AccessControlEntry("my-other-actor", Arrays.asList(READ));
          setRequest.addCurrentUser(currentUserAccessControlEntry);
          assertThat(setRequest.getAccessControlEntries(),
              containsInAnyOrder(
                  samePropertyValuesAs(currentUserAccessControlEntry),
                  samePropertyValuesAs(passedAccessControlEntry)));
        });

        it("should overwrite the entry passed in the request for the current user", () -> {
          // language=JSON
          String json = "{\n" +
              "\"name\":\"some-name\"," +
              "\"type\":\"password\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true, \n" +
              "\"access_control_entries\": [{\n" +
              "  \"actor\": \"my-actor\",\n" +
              "  \"operations\": [\"read\"]\n" +
              "}]\n" +
              "}";
          BaseSecretSetRequest setRequest = JsonHelper.deserialize(json, BaseSecretSetRequest.class);
          AccessControlEntry expectedEntry = new AccessControlEntry("my-actor", Arrays.asList(READ, WRITE));
          setRequest.addCurrentUser(expectedEntry);
          assertThat(setRequest.getAccessControlEntries(), equalTo(Arrays.asList(expectedEntry)));
        });
      });
    });
  }
}
