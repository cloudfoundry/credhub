package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import javax.validation.ConstraintViolation;
import java.io.IOException;
import java.util.Set;

import static org.cloudfoundry.credhub.helper.JsonTestHelper.deserializeAndValidate;
import static org.cloudfoundry.credhub.helper.JsonTestHelper.hasViolationWithMessage;
import static org.cloudfoundry.credhub.util.AuthConstants.USER_A_ACTOR_ID;
import static org.cloudfoundry.credhub.util.AuthConstants.USER_A_PATH;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;

@RunWith(JUnit4.class)
public class PermissionEntryTest {
  @Test
  public void validation_allowsGoodJson() throws IOException {
    String json = "{ \n"
        + "\"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
        + "\"operations\": [\"read\"],\n"
        + "\"path\": \"" + USER_A_PATH + "\""
        + "}";
    ObjectMapper om = new ObjectMapper();
    PermissionEntry permissionEntry = om.readValue(json, PermissionEntry.class);
    assertThat(permissionEntry.getActor(), equalTo(USER_A_ACTOR_ID));
    assertThat(permissionEntry.getPath(), equalTo(USER_A_PATH));
  }

  @Test
  public void validation_ensuresPresenceOfActor() {
    String json = "{ \n"
        + "\"operations\": [\"read\"],\n"
        + "\"path\": \"" + USER_A_PATH + "\""
        + "}";
    Set<ConstraintViolation<PermissionEntry>> constraintViolations = deserializeAndValidate(json, PermissionEntry.class);
    assertThat(constraintViolations, contains(hasViolationWithMessage("error.permission.missing_actor")));
  }

  @Test
  public void validation_ensuresActorIsNotEmpty() {
    String json = "{ \n"
        + "\"actor\":\"\","
        + "\"operations\": [\"read\"],\n"
        + "\"path\": \"" + USER_A_PATH + "\""
        + "}";
    Set<ConstraintViolation<PermissionEntry>> constraintViolations = deserializeAndValidate(json, PermissionEntry.class);
    assertThat(constraintViolations, contains(hasViolationWithMessage("error.permission.missing_actor")));
  }

  @Test
  public void validation_ensuresOperationsIsNotNull() {
    String json = "{"
        + "\"actor\": \"" + USER_A_ACTOR_ID + "\","
        + "\"path\": \"" + USER_A_PATH + "\""
        + "}";
    Set<ConstraintViolation<PermissionEntry>> constraintViolations = deserializeAndValidate(json, PermissionEntry.class);
    assertThat(constraintViolations, contains(hasViolationWithMessage("error.permission.missing_operations")));
  }

  @Test
  public void validation_ensuresOperationsIsNotEmpty() {
    String json = "{"
        + "\"actor\": \"" + USER_A_ACTOR_ID + "\","
        + "\"operations\": [],"
        + "\"path\": \"" + USER_A_PATH + "\""
        + "}";
    Set<ConstraintViolation<PermissionEntry>> constraintViolations = deserializeAndValidate(json, PermissionEntry.class);
    assertThat(constraintViolations, contains(hasViolationWithMessage("error.permission.missing_operations")));
  }

  @Test(expected = InvalidFormatException.class)
  public void validation_ensuresOperationsAreAllValid() throws Throwable {
    String json = "{ \n"
        + "\"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
        + "\"operations\": [\"foo\", \"read\"],\n"
        + "\"path\": \"" + USER_A_PATH + "\""
        + "}";
    try {
      deserializeAndValidate(json, PermissionEntry.class);
    } catch (RuntimeException e) {
      throw e.getCause();
    }
  }

  @Test
  public void validation_ensuresPathIsNotEmpty() {
    String json = "{"
        + "\"actor\": \"" + USER_A_ACTOR_ID + "\","
        + "\"operations\": [\"read\"]"
        + "}";
    Set<ConstraintViolation<PermissionEntry>> constraintViolations = deserializeAndValidate(json, PermissionEntry.class);
    assertThat(constraintViolations, contains(hasViolationWithMessage("error.permission.missing_path")));
  }
}
