package io.pivotal.security.request;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.deserialize;
import static io.pivotal.security.helper.JsonHelper.hasViolationWithMessage;
import static io.pivotal.security.helper.JsonHelper.serialize;
import static io.pivotal.security.helper.JsonHelper.validate;
import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.hamcrest.core.IsEqual.equalTo;

import com.greghaskins.spectrum.Spectrum;
import java.util.List;
import java.util.Set;
import javax.validation.ConstraintViolation;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class AccessEntriesRequestTest {

  {
    describe("validation", () -> {
      it("should allow good JSON", () -> {
        List<AccessControlEntry> entryList = newArrayList(
            new AccessControlEntry("someone", newArrayList(AccessControlOperation.READ)));
        AccessEntriesRequest original = new AccessEntriesRequest("test-name", entryList);
        byte[] json = serialize(original);
        AccessEntriesRequest actual = deserialize(json, AccessEntriesRequest.class);

        assertThat(actual.getCredentialName(), equalTo("test-name"));
        assertThat(actual.getAccessControlEntries(), contains(
            allOf(
                hasProperty("actor", equalTo("someone")),
                hasProperty("allowedOperations", hasItems(AccessControlOperation.READ))
            )
        ));
      });

      describe("#credential_name", () -> {
        it("should validate that credential_name is not null", () -> {
          List<AccessControlEntry> entryList = newArrayList(
              new AccessControlEntry("someone", newArrayList(AccessControlOperation.READ)));
          AccessEntriesRequest original = new AccessEntriesRequest(null, entryList);
          Set<ConstraintViolation<AccessEntriesRequest>> violations = validate(original);

          assertThat(violations.size(), equalTo(1));
          assertThat(violations, contains(hasViolationWithMessage("error.missing_name")));
        });

        it("should validate that credential_name is not empty", () -> {
          List<AccessControlEntry> entryList = newArrayList(
              new AccessControlEntry("someone", newArrayList(AccessControlOperation.READ)));
          AccessEntriesRequest original = new AccessEntriesRequest("", entryList);
          Set<ConstraintViolation<AccessEntriesRequest>> violations = validate(original);

          assertThat(violations.size(), equalTo(1));
          assertThat(violations, contains(hasViolationWithMessage("error.missing_name")));
        });
      });

      describe("#operations", () -> {
        it("should validate that operations is not null", () -> {
          AccessEntriesRequest original = new AccessEntriesRequest("foo", null);
          Set<ConstraintViolation<AccessEntriesRequest>> violations = validate(original);

          assertThat(violations.size(), equalTo(1));
          assertThat(violations, contains(hasViolationWithMessage("error.acl.missing_aces")));
        });

        it("should validate that credential_name is not empty", () -> {
          AccessEntriesRequest original = new AccessEntriesRequest("foo", newArrayList());
          Set<ConstraintViolation<AccessEntriesRequest>> violations = validate(original);

          assertThat(violations.size(), equalTo(1));
          assertThat(violations, contains(hasViolationWithMessage("error.acl.missing_aces")));
        });
      });
    });
  }
}
