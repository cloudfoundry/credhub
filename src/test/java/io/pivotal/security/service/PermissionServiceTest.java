package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.AccessControlDataService;
import io.pivotal.security.exceptions.PermissionException;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class PermissionServiceTest {
  private UserContext userContext;

  private PermissionService subject;

  private AccessControlDataService accessControlDataService;

  {
    beforeEach(() -> {
      userContext = mock(UserContext.class);
      when(userContext.getAclUser()).thenReturn("test-actor");

      accessControlDataService = mock(AccessControlDataService.class);

      subject = new PermissionService(accessControlDataService);
    });

    describe("#verifyAclReadPermission", () -> {
      describe("when the user has permission to read the credential's ACL", () -> {
        beforeEach(() -> {
          when(accessControlDataService.hasReadAclPermission("test-actor", "test-credential"))
              .thenReturn(true);
        });

        it("should do nothing", () -> {
          subject.verifyAclReadPermission(userContext, "test-credential");
          // pass
        });
      });

      describe("when the user does not have permission to read the credential's ACL", () -> {
        beforeEach(() -> {
          when(accessControlDataService.hasReadAclPermission("test-actor", "test-credential"))
              .thenReturn(false);
        });

        itThrowsWithMessage("throws", PermissionException.class, "error.acl.lacks_acl_read", () -> {
          subject.verifyAclReadPermission(userContext, "test-credential");
        });
      });
    });
  }
}
