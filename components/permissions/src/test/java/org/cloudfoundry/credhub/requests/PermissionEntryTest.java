package org.cloudfoundry.credhub.requests;

import java.io.IOException;
import java.util.Set;

import javax.validation.ConstraintViolation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import org.cloudfoundry.credhub.ErrorMessages;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.cloudfoundry.credhub.helpers.JsonTestHelper.deserializeAndValidate;
import static org.cloudfoundry.credhub.helpers.JsonTestHelper.hasViolationWithMessage;
import static org.cloudfoundry.credhub.utils.AuthConstants.USER_A_ACTOR_ID;
import static org.cloudfoundry.credhub.utils.AuthConstants.USER_A_PATH;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;

@RunWith(JUnit4.class)
public class PermissionEntryTest {
  @Test
  public void validation_allowsGoodJson() throws IOException {
    final String json = "{ \n"
      + "\"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
      + "\"operations\": [\"read\"],\n"
      + "\"path\": \"" + USER_A_PATH + "\""
      + "}";
    final ObjectMapper om = new ObjectMapper();
    final PermissionEntry permissionEntry = om.readValue(json, PermissionEntry.class);
    assertThat(permissionEntry.getActor(), equalTo(USER_A_ACTOR_ID));
    assertThat(permissionEntry.getPath(), equalTo(USER_A_PATH));
  }

  @Test
  public void validation_ensuresPresenceOfActor() {
    final String json = "{ \n"
      + "\"operations\": [\"read\"],\n"
      + "\"path\": \"" + USER_A_PATH + "\""
      + "}";
    final Set<ConstraintViolation<PermissionEntry>> constraintViolations = deserializeAndValidate(json, PermissionEntry.class);
    assertThat(constraintViolations, contains(hasViolationWithMessage(ErrorMessages.Permissions.MISSING_ACTOR)));
  }

  @Test
  public void validation_ensuresActorIsNotEmpty() {
    final String json = "{ \n"
      + "\"actor\":\"\","
      + "\"operations\": [\"read\"],\n"
      + "\"path\": \"" + USER_A_PATH + "\""
      + "}";
    final Set<ConstraintViolation<PermissionEntry>> constraintViolations = deserializeAndValidate(json, PermissionEntry.class);
    assertThat(constraintViolations, contains(hasViolationWithMessage(ErrorMessages.Permissions.MISSING_ACTOR)));
  }

  @Test
  public void validation_ensuresOperationsIsNotNull() {
    final String json = "{"
      + "\"actor\": \"" + USER_A_ACTOR_ID + "\","
      + "\"path\": \"" + USER_A_PATH + "\""
      + "}";
    final Set<ConstraintViolation<PermissionEntry>> constraintViolations = deserializeAndValidate(json, PermissionEntry.class);
    assertThat(constraintViolations, contains(hasViolationWithMessage(ErrorMessages.Permissions.MISSING_OPERATIONS)));
  }

  @Test
  public void validation_ensuresOperationsIsNotEmpty() {
    final String json = "{"
      + "\"actor\": \"" + USER_A_ACTOR_ID + "\","
      + "\"operations\": [],"
      + "\"path\": \"" + USER_A_PATH + "\""
      + "}";
    final Set<ConstraintViolation<PermissionEntry>> constraintViolations = deserializeAndValidate(json, PermissionEntry.class);
    assertThat(constraintViolations, contains(hasViolationWithMessage(ErrorMessages.Permissions.MISSING_OPERATIONS)));
  }

  @Test(expected = InvalidFormatException.class)
  public void validation_ensuresOperationsAreAllValid() throws Throwable {
    final String json = "{ \n"
      + "\"actor\": \"" + USER_A_ACTOR_ID + "\",\n"
      + "\"operations\": [\"foo\", \"read\"],\n"
      + "\"path\": \"" + USER_A_PATH + "\""
      + "}";
    try {
      deserializeAndValidate(json, PermissionEntry.class);
    } catch (final RuntimeException e) {
      throw e.getCause();
    }
  }

  @Test
  public void validation_ensuresPathIsNotEmpty() {
    final String json = "{"
      + "\"actor\": \"" + USER_A_ACTOR_ID + "\","
      + "\"operations\": [\"read\"]"
      + "}";
    final Set<ConstraintViolation<PermissionEntry>> constraintViolations = deserializeAndValidate(json, PermissionEntry.class);
    assertThat(constraintViolations, contains(hasViolationWithMessage(ErrorMessages.Permissions.MISSING_PATH)));
  }
}
