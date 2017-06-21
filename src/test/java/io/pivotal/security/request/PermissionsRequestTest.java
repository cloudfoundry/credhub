package io.pivotal.security.request;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

import java.util.List;
import java.util.Set;
import javax.validation.ConstraintViolation;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonTestHelper.deserialize;
import static io.pivotal.security.helper.JsonTestHelper.hasViolationWithMessage;
import static io.pivotal.security.helper.JsonTestHelper.serialize;
import static io.pivotal.security.helper.JsonTestHelper.validate;
import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(Spectrum.class)
public class PermissionsRequestTest {

  {
    describe("validation", () -> {
      it("should allow good JSON", () -> {
        List<PermissionEntry> entryList = newArrayList(
            new PermissionEntry("someone", newArrayList(PermissionOperation.READ)));
        PermissionsRequest original = new PermissionsRequest("test-name", entryList);
        byte[] json = serialize(original);
        PermissionsRequest actual = deserialize(json, PermissionsRequest.class);

        assertThat(actual.getCredentialName(), equalTo("test-name"));
        assertThat(actual.getPermissions(), contains(
            allOf(
                hasProperty("actor", equalTo("someone")),
                hasProperty("allowedOperations", hasItems(PermissionOperation.READ))
            )
        ));
      });

      describe("#credential_name", () -> {
        it("should validate that credential_name is not null", () -> {
          List<PermissionEntry> entryList = newArrayList(
              new PermissionEntry("someone", newArrayList(PermissionOperation.READ)));
          PermissionsRequest original = new PermissionsRequest(null, entryList);
          Set<ConstraintViolation<PermissionsRequest>> violations = validate(original);

          assertThat(violations.size(), equalTo(1));
          assertThat(violations, contains(hasViolationWithMessage("error.missing_name")));
        });

        it("should validate that credential_name is not empty", () -> {
          List<PermissionEntry> entryList = newArrayList(
              new PermissionEntry("someone", newArrayList(PermissionOperation.READ)));
          PermissionsRequest original = new PermissionsRequest("", entryList);
          Set<ConstraintViolation<PermissionsRequest>> violations = validate(original);

          assertThat(violations.size(), equalTo(1));
          assertThat(violations, contains(hasViolationWithMessage("error.missing_name")));
        });
      });

      describe("#operations", () -> {
        it("should validate that operations is not null", () -> {
          PermissionsRequest original = new PermissionsRequest("foo", null);
          Set<ConstraintViolation<PermissionsRequest>> violations = validate(original);

          assertThat(violations.size(), equalTo(1));
          assertThat(violations, contains(hasViolationWithMessage("error.acl.missing_aces")));
        });

        it("should validate that credential_name is not empty", () -> {
          PermissionsRequest original = new PermissionsRequest("foo", newArrayList());
          Set<ConstraintViolation<PermissionsRequest>> violations = validate(original);

          assertThat(violations.size(), equalTo(1));
          assertThat(violations, contains(hasViolationWithMessage("error.acl.missing_aces")));
        });
      });
    });
  }
}
