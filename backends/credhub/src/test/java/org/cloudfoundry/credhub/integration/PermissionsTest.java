package org.cloudfoundry.credhub.integration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.services.PermissionCheckingService;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.cloudfoundry.credhub.AuthConstants.ALL_PERMISSIONS_ACTOR_ID;
import static org.cloudfoundry.credhub.AuthConstants.NO_PERMISSIONS_ACTOR_ID;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_ACTOR_ID;
import static org.cloudfoundry.credhub.AuthConstants.USER_A_PATH;
import static org.cloudfoundry.credhub.AuthConstants.USER_B_ACTOR_ID;
import static org.cloudfoundry.credhub.AuthConstants.USER_B_PATH;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = CredhubTestApp.class)
@ActiveProfiles(
  value = {
    "unit-test",
    "unit-test-permissions",
  },
  resolver = DatabaseProfileResolver.class
)
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
@Transactional
public class PermissionsTest {
  private static final String PATH = "/my/credential";
  private static final String OTHER_PATH = "/my/other-credential";
  @Autowired
  private PermissionCheckingService subject;

  @Test
  public void testPermissionsWithoutWildcard() {
    assertThat(subject.hasPermission(USER_A_ACTOR_ID, "/user-a-cred", PermissionOperation.READ), is(true));
    assertThat(subject.hasPermission(USER_A_ACTOR_ID, "/user-b-cred", PermissionOperation.READ), is(false));
  }

  @Test
  public void testPermissionsWithWildcard() {
    assertThat(subject.hasPermission(USER_A_ACTOR_ID, USER_A_PATH + "anything", PermissionOperation.READ), is(true));
    assertThat(subject.hasPermission(USER_A_ACTOR_ID, USER_A_PATH + "anything", PermissionOperation.WRITE), is(true));
    assertThat(subject.hasPermission(USER_A_ACTOR_ID, USER_B_PATH + "anything", PermissionOperation.READ), is(false));

    assertThat(subject.hasPermission(USER_B_ACTOR_ID, USER_A_PATH + "anything", PermissionOperation.READ), is(false));
    assertThat(subject.hasPermission(USER_B_ACTOR_ID, USER_B_PATH + "anything", PermissionOperation.READ), is(true));
    assertThat(subject.hasPermission(USER_B_ACTOR_ID, USER_B_PATH + "anything", PermissionOperation.WRITE), is(true));

    assertThat(subject.hasPermission(USER_A_ACTOR_ID, "/shared-read-only/anything", PermissionOperation.READ), is(true));
    assertThat(subject.hasPermission(USER_A_ACTOR_ID, "/shared-read-only/anything", PermissionOperation.WRITE), is(false));

    assertThat(subject.hasPermission(ALL_PERMISSIONS_ACTOR_ID, USER_A_PATH + "anything", PermissionOperation.READ), is(true));
    assertThat(subject.hasPermission(ALL_PERMISSIONS_ACTOR_ID, USER_A_PATH + "anything", PermissionOperation.WRITE), is(true));
    assertThat(subject.hasPermission(ALL_PERMISSIONS_ACTOR_ID, USER_B_PATH + "anything", PermissionOperation.READ), is(true));
    assertThat(subject.hasPermission(ALL_PERMISSIONS_ACTOR_ID, USER_B_PATH + "anything", PermissionOperation.WRITE), is(true));
  }

  @Test
  public void testUnauthorizedPermissions() {
    assertThat(subject.hasPermission(NO_PERMISSIONS_ACTOR_ID, PATH, PermissionOperation.READ), is(false));
    assertThat(subject.hasPermission(NO_PERMISSIONS_ACTOR_ID, OTHER_PATH, PermissionOperation.READ), is(false));
  }
}
