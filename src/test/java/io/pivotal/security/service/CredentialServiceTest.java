package io.pivotal.security.service;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.constants.CredentialType;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.data.PermissionsDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.CredentialFactory;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.exceptions.InvalidAclOperationException;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.exceptions.PermissionException;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.PermissionOperation;
import io.pivotal.security.request.StringGenerationParameters;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static io.pivotal.security.audit.AuditingOperationCode.ACL_UPDATE;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.request.PermissionOperation.DELETE;
import static io.pivotal.security.request.PermissionOperation.READ;
import static io.pivotal.security.request.PermissionOperation.READ_ACL;
import static io.pivotal.security.request.PermissionOperation.WRITE;
import static io.pivotal.security.request.PermissionOperation.WRITE_ACL;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

@RunWith(JUnit4.class)
public class CredentialServiceTest {

  @Mock
  private CredentialDataService credentialDataService;

  @Mock
  private PermissionsDataService permissionsDataService;

  @Mock
  private PermissionService permissionService;

  @Mock
  private Encryptor encryptor;

  @Mock
  private CredentialFactory credentialFactory;

  private CredentialService subject;

  private Credential existingCredential;
  private UserContext userContext;
  private List<EventAuditRecordParameters> auditRecordParameters;
  private StringGenerationParameters generationParameters;
  private CredentialValue credentialValue;
  private List<PermissionEntry> accessControlEntries;
  private PermissionEntry currentUserPermissions;

  private static final String CREDENTIAL_NAME = "/Picard";

  @Before
  public void setUp() throws Exception {
    initMocks(this);

    subject = new CredentialService(
        credentialDataService,
        permissionsDataService,
        permissionService,
        credentialFactory);

    userContext = mock(UserContext.class);
    auditRecordParameters = new ArrayList<>();
    generationParameters = mock(StringGenerationParameters.class);
    credentialValue = mock(CredentialValue.class);
    accessControlEntries = new ArrayList<>();

    when(userContext.getAclUser()).thenReturn("Kirk");
    currentUserPermissions = new PermissionEntry(userContext.getAclUser(),
        Arrays.asList(READ, WRITE, DELETE, WRITE_ACL, READ_ACL));

    existingCredential = new PasswordCredential();
    existingCredential.setEncryptor(encryptor);
  }

  @Test(expected = ParameterizedValidationException.class)
  public void save_whenGivenTypeAndExistingTypeDontMatch_throwsException() {
    when(credentialDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredential);
    when(permissionService.hasPermission(userContext.getAclUser(), CREDENTIAL_NAME, WRITE))
        .thenReturn(true);
    subject.save(
        CREDENTIAL_NAME,
        "user",
        credentialValue,
        generationParameters,
        accessControlEntries,
        false,
        userContext,
        currentUserPermissions,
        auditRecordParameters
    );
  }

  @Test
  public void save_whenThereIsAnExistingCredentialAndOverwriteIsFalse_logsCREDENTIAL_ACCESS() {
    when(credentialDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredential);
    when(permissionService.hasPermission(userContext.getAclUser(), CREDENTIAL_NAME, WRITE))
        .thenReturn(true);
    subject.save(
        CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        false,
        userContext,
        currentUserPermissions,
        auditRecordParameters
    );

    assertThat(auditRecordParameters.get(0).getAuditingOperationCode(), equalTo(CREDENTIAL_ACCESS));
    assertThat(auditRecordParameters.get(0).getCredentialName(), equalTo(CREDENTIAL_NAME));
  }

  @Test
  public void save_whenThereIsAnExistingCredentialAndOverwriteIsTrue_logsCREDENTIAL_UPDATE() {
    when(credentialDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredential);
    when(credentialDataService.save(any(Credential.class)))
        .thenReturn(new PasswordCredential().setEncryptor(encryptor));
    when(permissionService.hasPermission(userContext.getAclUser(), CREDENTIAL_NAME, WRITE))
        .thenReturn(true);

    subject.save(
        CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        true,
        userContext,
        currentUserPermissions,
        auditRecordParameters
    );

    assertThat(auditRecordParameters.get(0).getAuditingOperationCode(), equalTo(CREDENTIAL_UPDATE));
    assertThat(auditRecordParameters.get(0).getCredentialName(), equalTo(CREDENTIAL_NAME));
  }

  @Test
  public void save_whenThereIsANewCredentialAndSelfUpdatingAcls_throwsException() {
    when(credentialDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(null);
    when(credentialDataService.save(any(Credential.class)))
        .thenReturn(new PasswordCredential().setEncryptor(encryptor));
    when(permissionService.validAclUpdateOperation(userContext, "test-user"))
        .thenReturn(false);

    accessControlEntries.add(new PermissionEntry("test-user", Arrays.asList(WRITE, WRITE_ACL)));
    try {

      subject.save(
          CREDENTIAL_NAME,
          "password",
          credentialValue,
          generationParameters,
          accessControlEntries,
          true,
          userContext,
          currentUserPermissions,
          auditRecordParameters
      );
    } catch (InvalidAclOperationException e) {
      assertThat(e.getMessage(), equalTo("error.acl.invalid_update_operation"));
    }
  }

  @Test
  public void save_whenThereIsAnExistingCredential_shouldCallVerifyCredentialWritePermission() {
    when(credentialDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredential);
    when(permissionService.hasPermission(userContext.getAclUser(), CREDENTIAL_NAME, WRITE)).thenReturn(true);
    subject.save(
        CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        false,
        userContext,
        currentUserPermissions,
        auditRecordParameters
    );

    verify(permissionService)
        .hasPermission(userContext.getAclUser(), CREDENTIAL_NAME, WRITE);
  }

  @Test
  public void save_whenThereIsNoExistingCredential_shouldNotCallVerifyCredentialWritePermission() {
    when(credentialDataService.save(any(Credential.class)))
        .thenReturn(new PasswordCredential().setEncryptor(encryptor));
    subject.save(
        CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        false,
        userContext,
        currentUserPermissions,
        auditRecordParameters
    );

    verify(permissionService, times(0))
        .hasPermission(userContext.getAclUser(), CREDENTIAL_NAME, WRITE);
  }

  @Test
  public void save_whenThereIsAnExistingCredentialWithACEs_shouldCallVerifyAclWritePermission() {
    when(credentialDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredential);
    when(permissionService.hasPermission(userContext.getAclUser(), CREDENTIAL_NAME, WRITE)).thenReturn(true);
    when(permissionService.hasPermission(userContext.getAclUser(), CREDENTIAL_NAME, WRITE_ACL)).thenReturn(true);
    when(permissionService.validAclUpdateOperation(userContext, "some_actor")).thenReturn(true);

    accessControlEntries
        .add(new PermissionEntry("some_actor", Arrays.asList(PermissionOperation.READ_ACL)));
    subject.save(
        CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        false,
        userContext,
        currentUserPermissions,
        auditRecordParameters
    );

    verify(permissionService)
        .hasPermission(userContext.getAclUser(), CREDENTIAL_NAME, WRITE_ACL);
  }

  @Test
  public void save_whenThereIsAnExistingCredentialWithACEs_shouldThrowAnExceptionIfItLacksPermission() {
    when(credentialDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredential);
    when(permissionService.hasPermission(userContext.getAclUser(), CREDENTIAL_NAME, WRITE_ACL)).thenReturn(false);

    accessControlEntries
        .add(new PermissionEntry("some_actor", Arrays.asList(PermissionOperation.READ_ACL)));

    try {
      subject.save(
          CREDENTIAL_NAME,
          "password",
          credentialValue,
          generationParameters,
          accessControlEntries,
          false,
          userContext,
          currentUserPermissions,
          auditRecordParameters
      );
    } catch (PermissionException pe) {
      assertThat(pe.getMessage(), equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void save_whenThereIsNoExistingCredential_shouldAddAceForTheCurrentUser() {
    when(credentialDataService.save(any(Credential.class)))
        .thenReturn(new PasswordCredential().setEncryptor(encryptor));
    subject.save(
        CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        false,
        userContext,
        currentUserPermissions,
        auditRecordParameters
    );

    assertThat(accessControlEntries, hasItem(
        samePropertyValuesAs(
            new PermissionEntry("Kirk", Arrays.asList(READ, WRITE, DELETE, WRITE_ACL, READ_ACL))
        )
        )
    );
  }

  @Test
  public void save_whenThereIsAnExistingCredentialAndOverWriteIsTrue_shouldNotAddAceForTheCurrentUser() {
    when(credentialDataService.save(any(Credential.class)))
        .thenReturn(new PasswordCredential().setEncryptor(encryptor));
    when(credentialDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredential);
    when(permissionService.hasPermission(userContext.getAclUser(), CREDENTIAL_NAME, WRITE))
        .thenReturn(true);

    subject.save(
        CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        true,
        userContext,
        currentUserPermissions,
        auditRecordParameters
    );

    assertThat(accessControlEntries, hasSize(0));
  }

  @Test
  public void save_whenWritingCredential_savesANewVersion() {
    when(credentialDataService.save(any(Credential.class)))
        .thenReturn(new PasswordCredential().setEncryptor(encryptor));
    final PasswordCredential newVersion = new PasswordCredential();

    when(credentialFactory.makeNewCredentialVersion(
        CredentialType.valueOf("password"),
        CREDENTIAL_NAME,
        credentialValue,
        null,
        generationParameters)).thenReturn(newVersion);

    subject.save(
        CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        true,
        userContext,
        currentUserPermissions,
        auditRecordParameters
    );

    verify(credentialDataService).save(newVersion);
  }

  @Test
  public void save_whenOverwriteIsTrue_shouldSaveAccessControlEntries() {
    PasswordCredential credential = new PasswordCredential().setEncryptor(encryptor);
    when(credentialDataService.save(any(Credential.class))).thenReturn(credential);

    subject.save(
        CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        true,
        userContext,
        currentUserPermissions,
        auditRecordParameters
    );

    verify(permissionsDataService)
        .saveAccessControlEntries(credential.getCredentialName(), accessControlEntries);
  }

  @Test
  public void save_whenOverwriteIsTrue_logsACL_UPDATE() {
    PasswordCredential credential = new PasswordCredential(CREDENTIAL_NAME).setEncryptor(encryptor);
    when(credentialDataService.save(any(Credential.class))).thenReturn(credential);
    when(permissionService.validAclUpdateOperation(userContext, "Spock")).thenReturn(true);
    when(permissionService.validAclUpdateOperation(userContext, "McCoy")).thenReturn(true);

    accessControlEntries.addAll(Arrays.asList(
        new PermissionEntry("Spock", Arrays.asList(WRITE)),
        new PermissionEntry("McCoy", Arrays.asList(DELETE))
    ));

    subject.save(
        CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        true,
        userContext,
        currentUserPermissions,
        auditRecordParameters
    );

    assertThat(auditRecordParameters, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, WRITE, "Spock")
        )));

    assertThat(auditRecordParameters, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, DELETE, "McCoy")
        )));

    assertThat(auditRecordParameters, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, DELETE, "Kirk")
        )));

    assertThat(auditRecordParameters, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, READ, "Kirk")
        )));

    assertThat(auditRecordParameters, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, WRITE, "Kirk")
        )));

    assertThat(auditRecordParameters, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, WRITE_ACL, "Kirk")
        )));

    assertThat(auditRecordParameters, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, READ_ACL, "Kirk")
        )));
  }
}
