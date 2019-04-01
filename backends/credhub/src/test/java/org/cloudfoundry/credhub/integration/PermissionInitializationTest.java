package org.cloudfoundry.credhub.integration;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.config.AuthorizationConfig;
import org.cloudfoundry.credhub.constants.CredentialType;
import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.data.PermissionData;
import org.cloudfoundry.credhub.repositories.PermissionRepository;
import org.cloudfoundry.credhub.requests.PasswordSetRequest;
import org.cloudfoundry.credhub.requests.PermissionEntry;
import org.cloudfoundry.credhub.services.DefaultPermissionService;
import org.cloudfoundry.credhub.services.DefaultPermissionedCredentialService;
import org.cloudfoundry.credhub.services.PermissionInitializer;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
@RunWith(SpringRunner.class)
@Transactional
public class PermissionInitializationTest {

  List<String> actors = Arrays.asList("uaa-user:test1", "uaa-user:test2");
  String credentialPath = "/my/credential";

  @Autowired
  private PermissionRepository permissionRepository;
  @Autowired
  private DefaultPermissionService permissionService;
  @Autowired
  private DefaultPermissionedCredentialService permissionedCredentialService;
  @Autowired
  private AuthorizationConfig permissions;
  @Autowired
  private ApplicationContext applicationContext;
  @Autowired
  private ApplicationEventPublisher applicationEventPublisher;

  @Before
  public void beforeEach() throws Exception {
    final List<AuthorizationConfig.Permission> permissions = new ArrayList<>();
    final AuthorizationConfig.Permission permission = new AuthorizationConfig.Permission();
    permission.setPath(credentialPath);

    permission.setActors(actors);
    permission.setOperations(Arrays.asList(PermissionOperation.READ, PermissionOperation.WRITE));
    permissions.add(permission);
    this.permissions.setPermissions(permissions);

    final StringCredentialValue password = new StringCredentialValue("password");
    final PasswordSetRequest passwordSetRequest = new PasswordSetRequest();
    passwordSetRequest.setName(credentialPath);
    passwordSetRequest.setType(CredentialType.PASSWORD.toString());
    permissionedCredentialService.save(null, password, passwordSetRequest);
  }

  @Test
  public void itAddsNewPermissions() {
    applicationEventPublisher.publishEvent(new ContextRefreshedEvent(applicationContext));

    final List<PermissionData> savedPermissions = permissionRepository.findAllByPath(credentialPath);
    assertThat(savedPermissions, hasSize(2));
    assertThat(savedPermissions.stream().map(p -> p.getActor()).collect(Collectors.toList()), containsInAnyOrder(actors.get(0), actors.get(1)));
    assertThat(savedPermissions.stream().allMatch(p -> p.hasReadPermission() && p.hasWritePermission()), is(true));
    assertThat(savedPermissions.stream().allMatch(p -> p.hasDeletePermission() && p.hasReadAclPermission() && p.hasWriteAclPermission()), is(false));
  }

  @Test
  public void itDoesNotOverwriteExistingPermissions() {
    final PermissionEntry permissionEntry = new PermissionEntry();
    permissionEntry.setActor(actors.get(0));
    permissionEntry.setAllowedOperations(Arrays.asList(PermissionOperation.READ, PermissionOperation.WRITE, PermissionOperation.READ_ACL, PermissionOperation.WRITE_ACL));
    permissionEntry.setPath("/test/path");
    permissionService.savePermissions(Arrays.asList(permissionEntry));

    applicationEventPublisher.publishEvent(new ContextRefreshedEvent(applicationContext));

    final List<PermissionData> savedPermissions = permissionRepository.findAllByPath(credentialPath);
    assertThat(savedPermissions, hasSize(2));
    assertThat(savedPermissions.stream().map(p -> p.getActor()).collect(Collectors.toList()), containsInAnyOrder(actors.get(0), actors.get(1)));
    assertThat(savedPermissions.stream().allMatch(p -> p.hasReadPermission() && p.hasWritePermission()), is(true));
    assertThat(savedPermissions.get(0).hasWriteAclPermission() && savedPermissions.get(1).hasWriteAclPermission(), is(false));
    assertThat(savedPermissions.get(0).hasReadAclPermission() && savedPermissions.get(1).hasReadAclPermission(), is(false));
    assertThat(savedPermissions.stream().allMatch(p -> p.hasDeletePermission()), is(false));
  }


  @Test
  public void itThrowsAnExceptionIfAuthorizationIsEmpty() {
    final PermissionInitializer initializer = new PermissionInitializer(null, new AuthorizationConfig());
    initializer.seed();
  }

  @Test
  public void itDoesntThrowAnExceptionIfAuthorizationConfigIsEmpty() {
    final PermissionInitializer initializer = new PermissionInitializer(null, null);
    initializer.seed();
  }
}
