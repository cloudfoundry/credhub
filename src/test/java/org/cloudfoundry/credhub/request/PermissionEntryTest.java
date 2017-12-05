package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;
import java.util.Set;
import javax.validation.ConstraintViolation;

import static org.cloudfoundry.credhub.helper.JsonTestHelper.deserializeAndValidate;
import static org.cloudfoundry.credhub.helper.JsonTestHelper.hasViolationWithMessage;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;

@RunWith(JUnit4.class)
public class PermissionEntryTest {
  @Test
  public void validation_allowsGoodJson() throws IOException {
    String json = "{ \n"
        + "\"actor\": \"dan\",\n"
        + "\"operations\": [\"read\"]\n"
        + "}";
    ObjectMapper om = new ObjectMapper();
    PermissionEntry permissionEntry = om.readValue(json, PermissionEntry.class);
    assertThat(permissionEntry.getActor(), equalTo("dan"));
  }

  @Test
  public void validation_ensuresPresenceOfActor() {
    String json = "{ \n"
        + "\"operations\": [\"read\"]\n"
        + "}";
    Set<ConstraintViolation<PermissionEntry>> constraintViolations = deserializeAndValidate(json, PermissionEntry.class);
    assertThat(constraintViolations, contains(hasViolationWithMessage("error.acl.missing_actor")));
  }

  @Test
  public void validation_ensuresActorIsNotEmpty() {
    String json = "{ \n"
        + "\"actor\":\"\","
        + "\"operations\": [\"read\"]\n"
        + "}";
    Set<ConstraintViolation<PermissionEntry>> constraintViolations = deserializeAndValidate(json, PermissionEntry.class);
    assertThat(constraintViolations, contains(hasViolationWithMessage("error.acl.missing_actor")));
  }

  @Test
  public void validation_ensuresOperationsIsNotNull() {
    String json = "{"
        + "\"actor\": \"dan\""
        + "}";
    Set<ConstraintViolation<PermissionEntry>> constraintViolations = deserializeAndValidate(json, PermissionEntry.class);
    assertThat(constraintViolations, contains(hasViolationWithMessage("error.permission.missing_operations")));
  }

  @Test
  public void validation_ensuresOperationsIsNotEmpty() {
    String json = "{"
        + "\"actor\": \"dan\","
        + "\"operations\": []"
        + "}";
    Set<ConstraintViolation<PermissionEntry>> constraintViolations = deserializeAndValidate(json, PermissionEntry.class);
    assertThat(constraintViolations, contains(hasViolationWithMessage("error.permission.missing_operations")));
  }

  @Test(expected = InvalidFormatException.class)
  public void validation_ensuresOperationsAreAllValid() throws Throwable {
    String json = "{ \n"
        + "\"actor\": \"dan\",\n"
        + "\"operations\": [\"foo\", \"read\"]\n"
        + "}";
    try {
      deserializeAndValidate(json, PermissionEntry.class);
    } catch (RuntimeException e) {
      throw e.getCause();
    }
  }
}
