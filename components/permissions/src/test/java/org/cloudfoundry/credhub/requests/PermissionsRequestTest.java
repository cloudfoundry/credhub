package org.cloudfoundry.credhub.requests;

import java.util.List;
import java.util.Set;

import javax.validation.ConstraintViolation;

import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.helpers.JsonTestHelper;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static com.google.common.collect.Lists.newArrayList;
import static org.cloudfoundry.credhub.helpers.JsonTestHelper.deserialize;
import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(JUnit4.class)
public class PermissionsRequestTest {
  @Test
  public void validation_allowsGoodJson() {
    final List<PermissionEntry> entryList = newArrayList(
      new PermissionEntry("someone", "test-path", newArrayList(PermissionOperation.READ)));
    final PermissionsRequest original = new PermissionsRequest("test-name", entryList);
    final byte[] json = JsonTestHelper.serialize(original);
    final PermissionsRequest actual = deserialize(json, PermissionsRequest.class);

    assertThat(actual.getCredentialName(), equalTo("/test-name"));
    assertThat(actual.getPermissions(), contains(
      allOf(
        hasProperty("actor", equalTo("someone")),
        hasProperty("allowedOperations", hasItems(PermissionOperation.READ))
      )
    ));
  }

  @Test
  public void validation_ensuresCredentialNameIsNotNull() {
    final List<PermissionEntry> entryList = newArrayList(
      new PermissionEntry("someone", "test-path", newArrayList(PermissionOperation.READ)));
    final PermissionsRequest original = new PermissionsRequest(null, entryList);
    final Set<ConstraintViolation<PermissionsRequest>> violations = JsonTestHelper.validate(original);

    assertThat(violations.size(), equalTo(1));
    MatcherAssert.assertThat(violations, Matchers.contains(JsonTestHelper.hasViolationWithMessage("error.missing_name")));
  }

  @Test
  public void validation_ensuresCredentialNameIsNotEmpty() {
    final List<PermissionEntry> entryList = newArrayList(
      new PermissionEntry("someone", "test-path", newArrayList(PermissionOperation.READ)));
    final PermissionsRequest original = new PermissionsRequest("", entryList);
    final Set<ConstraintViolation<PermissionsRequest>> violations = JsonTestHelper.validate(original);

    assertThat(violations.size(), equalTo(1));
    MatcherAssert.assertThat(violations, Matchers.contains(JsonTestHelper.hasViolationWithMessage("error.missing_name")));
  }

  @Test
  public void validation_ensuresOperationsIsNotNull() {
    final PermissionsRequest original = new PermissionsRequest("foo", null);
    final Set<ConstraintViolation<PermissionsRequest>> violations = JsonTestHelper.validate(original);

    assertThat(violations.size(), equalTo(1));
    MatcherAssert.assertThat(violations, Matchers.contains(JsonTestHelper.hasViolationWithMessage("error.permission.missing_aces")));
  }

  @Test
  public void validation_ensuresOperationsIsNotEmpty() {
    final PermissionsRequest original = new PermissionsRequest("foo", newArrayList());
    final Set<ConstraintViolation<PermissionsRequest>> violations = JsonTestHelper.validate(original);

    assertThat(violations.size(), equalTo(1));
    MatcherAssert.assertThat(violations, Matchers.contains(JsonTestHelper.hasViolationWithMessage("error.permission.missing_aces")));
  }
}
