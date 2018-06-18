package org.cloudfoundry.credhub.integration;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.config.Permissions;
import org.cloudfoundry.credhub.constants.CredentialType;
import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.PermissionData;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.repository.PermissionRepository;
import org.cloudfoundry.credhub.request.PasswordSetRequest;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.cloudfoundry.credhub.service.PermissionInitializer;
import org.cloudfoundry.credhub.service.PermissionService;
import org.cloudfoundry.credhub.service.PermissionedCredentialService;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@RunWith(SpringRunner.class)
@Transactional
public class PermissionInitializationTest {

  @Autowired
  private PermissionRepository permissionRepository;

  @Autowired
  private PermissionService permissionService;

  @Autowired
  private PermissionedCredentialService permissionedCredentialService;

  @Autowired
  private Permissions permissions;

  @Autowired
  private ApplicationContext applicationContext;

  @Autowired
  private ApplicationEventPublisher applicationEventPublisher;

  List<String> actors = Arrays.asList("uaa-user:test1", "uaa-user:test2");
  String credentialPath = "/my/credential";
  UUID credentialUUID;
  CredentialVersion credentialVersion;

  @Before
  public void beforeEach() throws Exception {
    List<Permissions.Permission> permissions = new ArrayList<>();
    Permissions.Permission permission = new Permissions.Permission();
    permission.setPath(credentialPath);

    permission.setActors(actors);
    permission.setOperations(Arrays.asList(PermissionOperation.READ, PermissionOperation.WRITE));
    permissions.add(permission);
    this.permissions.setPermissions(permissions);

    StringCredentialValue password = new StringCredentialValue("password");
    PasswordSetRequest passwordSetRequest = new PasswordSetRequest();
    passwordSetRequest.setName(credentialPath);
    passwordSetRequest.setType(CredentialType.password.toString());
    credentialVersion = permissionedCredentialService.save(null, password, passwordSetRequest);
    credentialUUID = credentialVersion.getCredential().getUuid();
  }

  @Test
  public void itAddsNewPermissions() {
    applicationEventPublisher.publishEvent(new ContextRefreshedEvent(applicationContext));

    List<PermissionData> savedPermissions = permissionRepository.findAllByCredentialUuid(credentialUUID);
    assertThat(savedPermissions, hasSize(2));
    assertThat(savedPermissions.stream().map(p -> p.getActor()).collect(Collectors.toList()), containsInAnyOrder(actors.get(0), actors.get(1)));
    assertThat(savedPermissions.stream().allMatch(p -> p.hasReadPermission() && p.hasWritePermission()), is(true));
    assertThat(savedPermissions.stream().allMatch(p -> p.hasDeletePermission() && p.hasReadAclPermission() && p.hasWriteAclPermission()), is(false));
  }

  @Test
  public void itDoesNotOverwriteExistingPermissions() {
    PermissionEntry permissionEntry = new PermissionEntry();
    permissionEntry.setActor(actors.get(0));
    permissionEntry.setAllowedOperations(Arrays.asList(PermissionOperation.READ, PermissionOperation.WRITE, PermissionOperation.READ_ACL, PermissionOperation.WRITE_ACL));
    permissionService.savePermissions(credentialVersion, Arrays.asList(permissionEntry));

    applicationEventPublisher.publishEvent(new ContextRefreshedEvent(applicationContext));

    List<PermissionData> savedPermissions = permissionRepository.findAllByCredentialUuid(credentialUUID);
    assertThat(savedPermissions, hasSize(2));
    assertThat(savedPermissions.stream().map(p -> p.getActor()).collect(Collectors.toList()), containsInAnyOrder(actors.get(0), actors.get(1)));
    assertThat(savedPermissions.stream().allMatch(p -> p.hasReadPermission() && p.hasWritePermission()), is(true));
    assertThat(savedPermissions.get(0).hasWriteAclPermission() && savedPermissions.get(0).hasReadAclPermission(), is(true));
    assertThat(savedPermissions.get(1).hasWriteAclPermission() || savedPermissions.get(1).hasReadAclPermission(), is(false));
    assertThat(savedPermissions.stream().allMatch(p -> p.hasDeletePermission()), is(false));
  }

  @Test(expected = EntryNotFoundException.class)
  public void itThrowsAnExceptionIfCredentialDoesntExist() {
    Permissions.Permission permission = new Permissions.Permission();
    permission.setPath("/doesnt/exist");
    permission.setActors(actors);
    permission.setOperations(Arrays.asList(PermissionOperation.READ));
    this.permissions.setPermissions(Arrays.asList(permission));

    applicationEventPublisher.publishEvent(new ContextRefreshedEvent(applicationContext));
  }

  @Test
  public void itDoesntThrowAnExceptionIfAuthorizationIsEmpty() {
    PermissionInitializer initializer = new PermissionInitializer(null, new Permissions(),null);
    initializer.seed();
  }

  @Test
  public void itDoesntThrowAnExceptionIfAuthorizationConfigIsEmpty() {
    PermissionInitializer initializer = new PermissionInitializer(null, null,null);
    initializer.seed();
  }
}
