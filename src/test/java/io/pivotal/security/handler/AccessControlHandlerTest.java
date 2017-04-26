package io.pivotal.security.handler;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.AccessControlDataService;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.repository.CredentialNameRepository;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import io.pivotal.security.request.AccessEntriesRequest;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.view.AccessControlListResponse;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class AccessControlHandlerTest {
  private AccessControlHandler subject;

  private PermissionService permissionService;
  private AccessControlDataService accessControlDataService;

  private final UserContext userContext = mock(UserContext.class);

  private CredentialNameRepository credentialNameRepository;

  public static final CredentialName CREDENTIAL_NAME = new CredentialName("/test-credential");

  {
    beforeEach(() -> {
      permissionService = mock(PermissionService.class);
      accessControlDataService = mock(AccessControlDataService.class);
      credentialNameRepository = mock(CredentialNameRepository.class);
      subject = new AccessControlHandler(permissionService, accessControlDataService, credentialNameRepository);

      when(credentialNameRepository.findOneByNameIgnoreCase(any(String.class))).thenReturn(CREDENTIAL_NAME);
    });

    describe("#getAccessControlListResponse", () -> {
      describe("when the requested credential name does not start with a slash", () -> {
        beforeEach(() -> {
          List<AccessControlEntry> accessControlList = newArrayList();
          when(accessControlDataService.getAccessControlList(any(CredentialName.class)))
              .thenReturn(accessControlList);
        });

        it("should ensure the response contains the corrected name", () -> {
          AccessControlListResponse response = subject.getAccessControlListResponse(
              null,
              "test-credential"
          );
          assertThat(response.getCredentialName(), equalTo("/test-credential"));
        });
      });

      describe("when there is an ACL", () -> {
        beforeEach(() -> {
          ArrayList<AccessControlOperation> operations = newArrayList(
              AccessControlOperation.READ,
              AccessControlOperation.WRITE
          );
          AccessControlEntry accessControlEntry = new AccessControlEntry(
              "test-actor",
              operations
          );
          List<AccessControlEntry> accessControlList = newArrayList(accessControlEntry);
          when(accessControlDataService.getAccessControlList(CREDENTIAL_NAME))
             .thenReturn(accessControlList);
        });

        it("verifies that the user has permission to read the credential's ACL", () -> {
          subject.getAccessControlListResponse(userContext, "/test-credential");

          verify(permissionService, times(1))
              .verifyAclReadPermission(userContext, CREDENTIAL_NAME);
        });

        it("should return the ACL response", () -> {
          AccessControlListResponse response = subject.getAccessControlListResponse(
              userContext,
              "/test-credential"
          );
          List<AccessControlEntry> accessControlEntries = response.getAccessControlList();

          assertThat(response.getCredentialName(), equalTo("/test-credential"));
          assertThat(accessControlEntries, hasSize(1));

          AccessControlEntry entry = accessControlEntries.get(0);
          assertThat(entry.getActor(), equalTo("test-actor"));

          List<AccessControlOperation> allowedOperations = entry.getAllowedOperations();
          assertThat(allowedOperations, contains(
              equalTo(AccessControlOperation.READ),
              equalTo(AccessControlOperation.WRITE)
          ));
        });
      });
    });

    describe("#setAccessControlListResponse", () -> {
      it("should set and return the ACEs", () -> {
        ArrayList<AccessControlOperation> operations = newArrayList(
            AccessControlOperation.READ,
            AccessControlOperation.WRITE
        );
        AccessControlEntry accessControlEntry = new AccessControlEntry("test-actor", operations);
        List<AccessControlEntry> accessControlList = newArrayList(accessControlEntry);

        AccessControlEntry preexistingAccessControlEntry = new AccessControlEntry(
            "someone-else",
            newArrayList(AccessControlOperation.READ)
        );
        List<AccessControlEntry> expectedControlList = newArrayList(accessControlEntry, preexistingAccessControlEntry);

        AccessEntriesRequest request = new AccessEntriesRequest("/test-credential", accessControlList);
        when(accessControlDataService.getAccessControlList(CREDENTIAL_NAME))
            .thenReturn(expectedControlList);


        AccessControlListResponse response = subject.setAccessControlEntries(request);

        List<AccessControlEntry> accessControlEntries = response.getAccessControlList();

        assertThat(response.getCredentialName(), equalTo("/test-credential"));
        assertThat(accessControlEntries, hasSize(2));

        AccessControlEntry entry1 = accessControlEntries.get(0);
        assertThat(entry1.getActor(), equalTo("test-actor"));
        assertThat(entry1.getAllowedOperations(), contains(
            equalTo(AccessControlOperation.READ),
            equalTo(AccessControlOperation.WRITE)
        ));

        AccessControlEntry entry2 = accessControlEntries.get(1);
        assertThat(entry2.getActor(), equalTo("someone-else"));
        assertThat(entry2.getAllowedOperations(), contains(equalTo(AccessControlOperation.READ)));
      });
    });

    describe("#deleteAccessControlListResponse", () -> {
      beforeEach(() -> {
        when(credentialNameRepository.findOneByNameIgnoreCase(any(String.class))).thenReturn(CREDENTIAL_NAME);
      });

      it("should delete the actor's ACEs for the specified credential", () -> {
        subject.deleteAccessControlEntries( "test-actor", "/test-credential");

        verify(accessControlDataService, times(1)).deleteAccessControlEntries(
            "test-actor", CREDENTIAL_NAME);
      });
    });
  }
}
