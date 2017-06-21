package io.pivotal.security.request;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.helper.JsonTestHelper;
import org.junit.runner.RunWith;

import java.util.Arrays;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonTestHelper.deserializeChecked;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.request.PermissionOperation.READ;
import static io.pivotal.security.request.PermissionOperation.WRITE;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

@RunWith(Spectrum.class)
public class BaseCredentialSetRequestTest {

  {
    describe("when type is not set", () -> {
      itThrows("should throw an JsonMappingException", JsonMappingException.class, () -> {
        String json = "{" +
            "\"name\":\"some-name\"," +
            "\"value\":\"some-value\"," +
            "\"overwrite\":true" +
            "}";

        JsonTestHelper.deserializeChecked(json, BaseCredentialSetRequest.class);
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

        JsonTestHelper.deserializeChecked(json, BaseCredentialSetRequest.class);
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

        JsonTestHelper.deserializeChecked(json, BaseCredentialSetRequest.class);
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
            BaseCredentialSetRequest.class);
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
          BaseCredentialSetRequest setRequest = JsonTestHelper.deserialize(json, BaseCredentialSetRequest.class);
          PermissionEntry expectedEntry = new PermissionEntry("my-actor", Arrays.asList(READ, WRITE));
          setRequest.addCurrentUser(expectedEntry);
          assertThat(setRequest.getAdditionalPermissions(), equalTo(Arrays.asList(expectedEntry)));
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
              "\"additional_permissions\": [{\n" +
              "  \"actor\": \"my-other-actor\",\n" +
              "  \"operations\": [\"read\"]\n" +
              "}]\n" +
              "}";
          BaseCredentialSetRequest setRequest = JsonTestHelper.deserialize(json, BaseCredentialSetRequest.class);
          PermissionEntry currentUserPermissionEntry =
              new PermissionEntry("my-actor", Arrays.asList(READ, WRITE));
          PermissionEntry passedPermissionEntry =
              new PermissionEntry("my-other-actor", Arrays.asList(READ));
          setRequest.addCurrentUser(currentUserPermissionEntry);
          assertThat(setRequest.getAdditionalPermissions(),
              containsInAnyOrder(
                  samePropertyValuesAs(currentUserPermissionEntry),
                  samePropertyValuesAs(passedPermissionEntry)));
        });

        it("should overwrite the entry passed in the request for the current user", () -> {
          // language=JSON
          String json = "{\n" +
              "\"name\":\"some-name\"," +
              "\"type\":\"password\"," +
              "\"value\":\"some-value\"," +
              "\"overwrite\":true, \n" +
              "\"additional_permissions\": [{\n" +
              "  \"actor\": \"my-actor\",\n" +
              "  \"operations\": [\"read\"]\n" +
              "}]\n" +
              "}";
          BaseCredentialSetRequest setRequest = JsonTestHelper.deserialize(json, BaseCredentialSetRequest.class);
          PermissionEntry expectedEntry = new PermissionEntry("my-actor", Arrays.asList(READ, WRITE));
          setRequest.addCurrentUser(expectedEntry);
          assertThat(setRequest.getAdditionalPermissions(), equalTo(Arrays.asList(expectedEntry)));
        });
      });
    });
  }
}
