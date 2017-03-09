package io.pivotal.security.request;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

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

import java.util.List;
import java.util.Set;

import javax.validation.ConstraintViolation;

@RunWith(Spectrum.class)
public class AccessEntryRequestTest {
  {
    describe("validation", () -> {
      it("should allow good JSON", () -> {
        List<AccessControlEntry> entryList = newArrayList(new AccessControlEntry("someone", newArrayList(AccessControlOperation.READ)));
        AccessEntryRequest original = new AccessEntryRequest("test-name", entryList);
        byte[] json = serialize(original);
        AccessEntryRequest actual = deserialize(json, AccessEntryRequest.class);

        assertThat(actual.getCredentialName(), equalTo("test-name"));
        assertThat(actual.getAccessControlEntries(), contains(
            allOf(
                hasProperty("actor", equalTo("someone")),
                hasProperty("operations", hasItems(AccessControlOperation.READ))
            )
        ));
      });

      describe("#credential_name", () -> {
        it("should validate that credential_name is not null", () -> {
          List<AccessControlEntry> entryList = newArrayList(new AccessControlEntry("someone", newArrayList(AccessControlOperation.READ)));
          AccessEntryRequest original = new AccessEntryRequest(null, entryList);
          Set<ConstraintViolation<AccessEntryRequest>> violations = validate(original);

          assertThat(violations.size(), equalTo(1));
          assertThat(violations, contains(hasViolationWithMessage("error.missing_name")));
        });

        it("should validate that credential_name is not empty", () -> {
          List<AccessControlEntry> entryList = newArrayList(new AccessControlEntry("someone", newArrayList(AccessControlOperation.READ)));
          AccessEntryRequest original = new AccessEntryRequest("", entryList);
          Set<ConstraintViolation<AccessEntryRequest>> violations = validate(original);

          assertThat(violations.size(), equalTo(1));
          assertThat(violations, contains(hasViolationWithMessage("error.missing_name")));
        });
      });

      describe("#operations", () -> {
        it("should validate that operations is not null", () -> {
          AccessEntryRequest original = new AccessEntryRequest("foo", null);
          Set<ConstraintViolation<AccessEntryRequest>> violations = validate(original);

          assertThat(violations.size(), equalTo(1));
          assertThat(violations, contains(hasViolationWithMessage("error.acl.missing_aces")));
        });

        it("should validate that credential_name is not empty", () -> {
          AccessEntryRequest original = new AccessEntryRequest("foo", newArrayList());
          Set<ConstraintViolation<AccessEntryRequest>> violations = validate(original);

          assertThat(violations.size(), equalTo(1));
          assertThat(violations, contains(hasViolationWithMessage("error.acl.missing_aces")));
        });
      });
    });
  }
}
