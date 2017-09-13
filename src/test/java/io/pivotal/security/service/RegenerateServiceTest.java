package io.pivotal.security.service;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.credential.RsaCredentialValue;
import io.pivotal.security.credential.SshCredentialValue;
import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.credential.UserCredentialValue;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.CertificateCredential;
import io.pivotal.security.domain.JsonCredential;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.domain.RsaCredential;
import io.pivotal.security.domain.SshCredential;
import io.pivotal.security.domain.UserCredential;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.exceptions.PermissionException;
import io.pivotal.security.request.CredentialRegenerateRequest;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.PermissionOperation;
import io.pivotal.security.request.RsaGenerationParameters;
import io.pivotal.security.request.SshGenerationParameters;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.util.CertificateReader;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyList;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class RegenerateServiceTest {

  private CredentialDataService credentialDataService;
  private RegenerateService subject;

  private StringGenerationParameters expectedParameters;
  private List<EventAuditRecordParameters> auditRecordParameters;
  private CredentialService credentialService;
  private PermissionEntry currentUser;

  private GeneratorService generatorService;
  private PermissionService permissionService;

  public UserContext userContext;

  @Before
  public void beforeEach() {
    credentialDataService = mock(CredentialDataService.class);
    auditRecordParameters = newArrayList();
    credentialService = mock(CredentialService.class);
    generatorService = mock(GeneratorService.class);
    userContext = mock(UserContext.class);
    currentUser = mock(PermissionEntry.class);
    permissionService = mock(PermissionService.class);

    when(userContext.getAclUser()).thenReturn("expected user");
    when(permissionService.hasPermission(eq("expected user"), anyString(), any(PermissionOperation.class)))
        .thenReturn(true);

    subject = new RegenerateService(credentialDataService, credentialService,
        generatorService, permissionService);
  }

  @Test
  public void performRegenerateByName_shouldRegenerateAPassword() {
    PasswordCredential passwordCredential = mock(PasswordCredential.class);
    StringCredentialValue newPassword = mock(StringCredentialValue.class);
    when(credentialDataService.findMostRecent(eq("password")))
        .thenReturn(passwordCredential);
    CredentialRegenerateRequest passwordGenerateRequest = new CredentialRegenerateRequest();
    passwordGenerateRequest.setName("password");
    expectedParameters = new StringGenerationParameters()
        .setExcludeLower(true)
        .setExcludeUpper(true)
        .setLength(20);
    when(passwordCredential.getName()).thenReturn("password");
    when(passwordCredential.getCredentialType()).thenReturn("password");
    when(passwordCredential.getGenerationParameters())
        .thenReturn(expectedParameters);
    when(generatorService.generatePassword(eq(expectedParameters)))
        .thenReturn(newPassword);

    subject
        .performRegenerate(passwordGenerateRequest.getName(), userContext,
            currentUser, auditRecordParameters
        );

    verify(credentialService)
        .save(
            eq("password"),
            eq("password"),
            eq(newPassword),
            eq(expectedParameters),
            eq(Collections.emptyList()),
            eq(true),
            eq(userContext),
            eq(currentUser),
            eq(auditRecordParameters)
        );
  }

  @Test
  public void performRegenerateByName_onANonGeneratedPassword_failsToRegenerate() {
    PasswordCredential passwordCredential = mock(PasswordCredential.class);
    when(credentialDataService.findMostRecent(eq("password"))).thenReturn(passwordCredential);
    when(passwordCredential.getName()).thenReturn("password");
    when(passwordCredential.getCredentialType()).thenReturn("password");
    when(passwordCredential.getGenerationParameters()).thenReturn(null);

    CredentialRegenerateRequest passwordGenerateRequest = new CredentialRegenerateRequest();
    passwordGenerateRequest.setName("password");

    try {
      subject
          .performRegenerate(passwordGenerateRequest.getName(), userContext, currentUser, auditRecordParameters);
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.cannot_regenerate_non_generated_password"));
    }
  }

  @Test
  public void performRegenerateByName_regeneratesAUser() {
    UserCredential userCredential = mock(UserCredential.class);
    UserCredentialValue newUser = mock(UserCredentialValue.class);
    when(credentialDataService.findMostRecent(eq("user"))).thenReturn(userCredential);
    CredentialRegenerateRequest userGenerateRequest = new CredentialRegenerateRequest();
    userGenerateRequest.setName("user");
    expectedParameters = new StringGenerationParameters()
        .setExcludeLower(true)
        .setExcludeUpper(true)
        .setLength(20)
        .setUsername("Darth Vader");
    when(userCredential.getName()).thenReturn("user");
    when(userCredential.getCredentialType()).thenReturn("user");
    when(userCredential.getGenerationParameters())
        .thenReturn(expectedParameters);
    when(userCredential.getUsername()).thenReturn("Darth Vader");
    when(generatorService.generateUser(eq("Darth Vader"), eq(expectedParameters)))
        .thenReturn(newUser);

    subject
        .performRegenerate(userGenerateRequest.getName(), userContext,
            currentUser, auditRecordParameters
        );

    verify(credentialService)
        .save(
            eq("user"),
            eq("user"),
            eq(newUser),
            eq(expectedParameters),
            eq(Collections.emptyList()),
            eq(true),
            eq(userContext),
            eq(currentUser),
            eq(auditRecordParameters)
        );
  }

  @Test
  public void performRegenerate_onNonGeneratedUser_failsToRegenerate() {
    UserCredential userCredential = mock(UserCredential.class);
    when(credentialDataService.findMostRecent(eq("user"))).thenReturn(userCredential);
    when(userCredential.getName()).thenReturn("user");
    when(userCredential.getCredentialType()).thenReturn("user");
    when(userCredential.getUsername()).thenReturn("Darth Vader");
    when(userCredential.getGenerationParameters()).thenReturn(null);

    CredentialRegenerateRequest userGenerateRequest = new CredentialRegenerateRequest();
    userGenerateRequest.setName("user");

    try {
      subject
          .performRegenerate(userGenerateRequest.getName(), userContext, currentUser, auditRecordParameters);
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.cannot_regenerate_non_generated_user"));
    }
  }

  @Test
  public void performRegenerate_regeneratesACertificate() {
    final CertificateCredential certificateCredential = mock(CertificateCredential.class);
    when(credentialDataService.findMostRecent("certificate")).thenReturn(certificateCredential);
  }

  @Test
  public void performRegenerate_regeneratesSshCredential() {
    SshCredential sshCredential = mock(SshCredential.class);
    SshCredentialValue regeneratedSsh = mock(SshCredentialValue.class);
    when(credentialDataService.findMostRecent(eq("ssh")))
        .thenReturn(sshCredential);
    CredentialRegenerateRequest sshRegenerateRequest = new CredentialRegenerateRequest();
    sshRegenerateRequest.setName("ssh");
    when(sshCredential.getName()).thenReturn("ssh");
    when(sshCredential.getCredentialType()).thenReturn("ssh");

    when(generatorService.generateSshKeys(any(SshGenerationParameters.class)))
        .thenReturn(regeneratedSsh);

    subject
        .performRegenerate(sshRegenerateRequest.getName(), userContext, currentUser, auditRecordParameters);

    verify(credentialService)
        .save(
            eq("ssh"),
            eq("ssh"),
            eq(regeneratedSsh),
            eq(null),
            eq(Collections.emptyList()),
            eq(true),
            eq(userContext),
            eq(currentUser),
            eq(auditRecordParameters)
        );
  }

  @Test
  public void performRegenerate_regeneratesRsaCredential() {
    RsaCredential rsaCredential = mock(RsaCredential.class);
    RsaCredentialValue regeneratedRsa = mock(RsaCredentialValue.class);

    when(credentialDataService.findMostRecent(eq("rsa")))
        .thenReturn(rsaCredential);
    CredentialRegenerateRequest rsaRegenerateRequest = new CredentialRegenerateRequest();
    rsaRegenerateRequest.setName("rsa");
    when(rsaCredential.getName()).thenReturn("rsa");
    when(rsaCredential.getCredentialType()).thenReturn("rsa");
    when(generatorService.generateRsaKeys(any(RsaGenerationParameters.class)))
        .thenReturn(regeneratedRsa);

    subject
        .performRegenerate(rsaRegenerateRequest.getName(), userContext, currentUser, auditRecordParameters);

    verify(credentialService)
        .save(
            eq("rsa"),
            eq("rsa"),
            eq(regeneratedRsa),
            eq(null),
            eq(Collections.emptyList()),
            eq(true),
            eq(userContext),
            eq(currentUser),
            eq(auditRecordParameters)
        );
  }

  @Test(expected = EntryNotFoundException.class)
  public void performRegenerate_whenRegeneratingANonExistentCredential_throwsAnException() {

    CredentialRegenerateRequest passwordGenerateRequest = new CredentialRegenerateRequest();
    passwordGenerateRequest.setName("missing_entry");

    subject.performRegenerate(passwordGenerateRequest.getName(), userContext, currentUser, auditRecordParameters);
  }

  @Test(expected = ParameterizedValidationException.class)
  public void performRegenerate_whenRegeneratingANonRegeneratableType_throwsAnException() {
    JsonCredential credentialOfUnsupportedType = new JsonCredential();
    when(credentialDataService.findMostRecent(eq("unsupported")))
        .thenReturn(credentialOfUnsupportedType);

    CredentialRegenerateRequest passwordGenerateRequest = new CredentialRegenerateRequest();
    passwordGenerateRequest.setName("unsupported");

    subject.performRegenerate(passwordGenerateRequest.getName(), userContext, currentUser, auditRecordParameters);
  }

  @Test
  public void performBulkRegenerate_regeneratesCertificatesSignedByGivenSigner(){
    when(credentialDataService.findAllCertificateCredentialsByCaName("/some-signer-name")).thenReturn(
        Collections.singletonList("cert1"));
    when(permissionService.hasPermission(any(), eq("/some-signer-name"), eq(PermissionOperation.READ))).thenReturn(true);

    CertificateCredential credential = mock(CertificateCredential.class);
    when(credential.getCredentialType()).thenReturn("certificate");
    final CertificateReader reader = mock(CertificateReader.class);
    when(credential.getParsedCertificate()).thenReturn(reader);
    when(credential.getCaName()).thenReturn("mock_ca");
    when(credential.getName()).thenReturn("cert1");
    when(reader.isValid()).thenReturn(true);

    when(credentialDataService.findMostRecent("cert1")).thenReturn(credential);

    subject.performBulkRegenerate("/some-signer-name", userContext,
        mock(PermissionEntry.class), new ArrayList<>());

    verify(credentialService).save(eq("cert1"), eq("certificate"), any(CredentialValue.class), any(
        StringGenerationParameters.class), anyList(), eq(true), any(UserContext.class), any(PermissionEntry.class), anyList());
  }

  @Test
  public void performBulkRegenerate_regeneratesEachCredentialOnlyOnce() {
    when(credentialDataService.findAllCertificateCredentialsByCaName("/some-signer-name")).thenReturn(
        Arrays.asList("cert1", "cert1", "cert1"));
    when(permissionService.hasPermission(any(), eq("/some-signer-name"), eq(PermissionOperation.READ))).thenReturn(true);

    CertificateCredential credential = mock(CertificateCredential.class);
    when(credential.getCredentialType()).thenReturn("certificate");
    final CertificateReader reader = mock(CertificateReader.class);
    when(credential.getParsedCertificate()).thenReturn(reader);
    when(credential.getCaName()).thenReturn("mock_ca");
    when(credential.getName()).thenReturn("cert1");
    when(reader.isValid()).thenReturn(true);

    when(credentialDataService.findMostRecent("cert1")).thenReturn(credential);

    subject.performBulkRegenerate("/some-signer-name", userContext,
        mock(PermissionEntry.class), new ArrayList<>());

    verify(credentialService).save(eq("cert1"), eq("certificate"), any(CredentialValue.class), any(
        StringGenerationParameters.class), anyList(), eq(true), any(UserContext.class), any(PermissionEntry.class), anyList());
  }

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void performBulkRegenerate_whenUserHasReadPermissions_throwsPermissionException() throws PermissionException {
    String user = "test-user";
    String caName = "/some-signer-name";
    when(userContext.getAclUser()).thenReturn(user);
    when(permissionService.hasPermission(eq(user), eq("/some-signer-name"), eq(PermissionOperation.READ))).thenReturn(false);

    thrown.expect(PermissionException.class);
    thrown.expectMessage("error.credential.invalid_access");
    subject.performBulkRegenerate(caName, userContext, mock(PermissionEntry.class), newArrayList());
  }
}
