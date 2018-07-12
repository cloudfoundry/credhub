package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import org.cloudfoundry.credhub.helper.JsonTestHelper;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.util.Arrays;

import static org.cloudfoundry.credhub.helper.JsonTestHelper.deserializeChecked;
import static org.cloudfoundry.credhub.request.PermissionOperation.READ;
import static org.cloudfoundry.credhub.request.PermissionOperation.WRITE;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.junit.Assert.assertThat;

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

  @Test
  public void addCurrentUser_whenThereAreNoPermissionsInRequest_addsPermissionsForCurrentUser() {
    // language=JSON
    String json = "{\n" +
        "\"name\":\"some-name\"," +
        "\"type\":\"password\"," +
        "\"value\":\"some-value\"" +
        "}";
    BaseCredentialSetRequest setRequest = JsonTestHelper.deserialize(json, BaseCredentialSetRequest.class);
    PermissionEntry expectedEntry = new PermissionEntry("my-actor", "test-path", Arrays.asList(READ, WRITE));

    setRequest.addCurrentUser(expectedEntry);

    assertThat(setRequest.getAdditionalPermissions(), equalTo(Arrays.asList(expectedEntry)));
  }

  @Test
  public void addCurrentUser_whenThereArePermissionsInRequest_addsPermissionsForCurrentUser() {
    // language=JSON
    String json = "{\n" +
        "\"name\":\"test-path\"," +
        "\"type\":\"password\"," +
        "\"value\":\"some-value\"," +
        "\"additional_permissions\": [{\n" +
        "  \"actor\": \"my-other-actor\",\n" +
        "  \"operations\": [\"read\"],\n" +
        "  \"path\": \"test-path\"\n" +
        "}]\n" +
        "}";
    BaseCredentialSetRequest setRequest = JsonTestHelper.deserialize(json, BaseCredentialSetRequest.class);
    PermissionEntry currentUserPermissionEntry =
        new PermissionEntry("my-actor", "test-path", Arrays.asList(READ, WRITE));
    PermissionEntry passedPermissionEntry =
        new PermissionEntry("my-other-actor", "test-path", Arrays.asList(READ));
    setRequest.addCurrentUser(currentUserPermissionEntry);
    assertThat(setRequest.getAdditionalPermissions(),
        containsInAnyOrder(
            samePropertyValuesAs(currentUserPermissionEntry),
            samePropertyValuesAs(passedPermissionEntry)));
  }

  @Test
  public void addCurrentUser_whenThereArePermissionsForCurrentUser_overwritesPermissionsForCurrentUser() {
    // language=JSON
    String json = "{\n" +
        "\"name\":\"some-name\"," +
        "\"type\":\"password\"," +
        "\"value\":\"some-value\"," +
        "\"additional_permissions\": [{\n" +
        "  \"actor\": \"my-actor\",\n" +
        "  \"operations\": [\"read\"]\n" +
        "}]\n" +
        "}";
    BaseCredentialSetRequest setRequest = JsonTestHelper.deserialize(json, BaseCredentialSetRequest.class);
    PermissionEntry expectedEntry = new PermissionEntry("my-actor", "test-path", Arrays.asList(READ, WRITE));

    setRequest.addCurrentUser(expectedEntry);

    assertThat(setRequest.getAdditionalPermissions(), equalTo(Arrays.asList(expectedEntry)));
  }
}
