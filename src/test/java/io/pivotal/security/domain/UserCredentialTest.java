package io.pivotal.security.domain;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.UserCredentialData;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.UserSetRequestFields;
import io.pivotal.security.service.Encryption;
import org.junit.runner.RunWith;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.UUID;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.request.AccessControlOperation.READ;
import static io.pivotal.security.request.AccessControlOperation.WRITE;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

@RunWith(Spectrum.class)
public class UserCredentialTest {
  private UserCredential subject;
  private Encryptor encryptor;
  private final String CREDENTIAL_NAME = "/test/user";
  private final String USER_PASSWORD = "test-user-password";
  private final String USERNAME = "test-username";
  private final UUID ENCRYPTION_KEY_UUID = UUID.randomUUID();
  private final byte[] ENCRYPTED_PASSWORD = "encrypted-user-password".getBytes();
  private final byte[] NONCE = "user-NONCE".getBytes();
  private UserCredential NO_EXISTING_CREDENTIAL = null;
  private UserCredentialData userCredentialData;

  {
    beforeEach(() -> {
      encryptor = mock(Encryptor.class);
    });

    describe("#getCredentialType", () -> {
      it("should return user type", () -> {
        subject = new UserCredential();
        assertThat(subject.getCredentialType(), equalTo("user"));
      });
    });

    describe("#getUsername", () -> {
      it("gets username from the delegate", () -> {
        subject = new UserCredential(
            new UserCredentialData(CREDENTIAL_NAME).setUsername("test-user"));
        assertThat(subject.getUsername(), equalTo("test-user"));
      });
    });

    describe("#setUsername", () -> {
      it("sets username on the delegate", () -> {
        UserCredentialData delegate = new UserCredentialData(CREDENTIAL_NAME);
        subject = new UserCredential(delegate);
        subject.setUsername("test-user");
        assertThat(delegate.getUsername(), equalTo("test-user"));
      });
    });

    describe("#getPassword", () -> {
      beforeEach(() -> {
        when(encryptor.decrypt(
            eq(ENCRYPTION_KEY_UUID), eq(ENCRYPTED_PASSWORD), eq(NONCE)))
            .thenReturn(USER_PASSWORD);
        userCredentialData = new UserCredentialData()
            .setEncryptedValue(ENCRYPTED_PASSWORD)
            .setNonce(NONCE)
            .setEncryptionKeyUuid(ENCRYPTION_KEY_UUID);
        subject = new UserCredential(userCredentialData)
            .setEncryptor(encryptor);
      });

      it("should return decrypted password", () -> {
        assertThat(subject.getPassword(), equalTo(USER_PASSWORD));
      });

      it("should call decrypt once", () -> {
        subject.getPassword();
        verify(encryptor, times(1)).decrypt(any(), any(), any());
      });
    });

    describe("setPassword", () -> {
      beforeEach(() -> {
        when(encryptor.encrypt(eq(USER_PASSWORD)))
            .thenReturn(new Encryption(ENCRYPTION_KEY_UUID, ENCRYPTED_PASSWORD, NONCE));
        userCredentialData = new UserCredentialData(CREDENTIAL_NAME);
        subject = new UserCredential(userCredentialData)
            .setEncryptor(encryptor);
        subject.setPassword(USER_PASSWORD);
      });

      it("should encrypt provided password", () -> {
        verify(encryptor, times(1)).encrypt(eq(USER_PASSWORD));
      });

      it("sets encryption key uuid, encrypted value and the nonce on the delegate", () -> {
        subject.setPassword(USER_PASSWORD);

        assertThat(userCredentialData.getEncryptionKeyUuid(), equalTo(ENCRYPTION_KEY_UUID));
        assertThat(userCredentialData.getEncryptedValue(), equalTo(ENCRYPTED_PASSWORD));
        assertThat(userCredentialData.getNonce(), equalTo(NONCE));
      });
    });

    describe("create new version", () -> {
      beforeEach(() -> {
        when(encryptor.encrypt(eq(USER_PASSWORD)))
            .thenReturn(new Encryption(ENCRYPTION_KEY_UUID, ENCRYPTED_PASSWORD, NONCE));
      });

      describe("when there is an existing credential", () -> {
        it("should set name reference from existing credential if present", () -> {
          UserCredentialData existingUserCredentialData = new UserCredentialData(CREDENTIAL_NAME);
          subject = UserCredential.createNewVersion(
              new UserCredential(existingUserCredentialData),
              CREDENTIAL_NAME,
              new UserSetRequestFields()
                  .setPassword(USER_PASSWORD)
                  .setUsername(USERNAME),
              encryptor,
              newArrayList());

          assertThat(subject.getCredentialName(), equalTo(existingUserCredentialData.getCredentialName()));
        });
      });

      describe("when there is no existing credential", () -> {
        beforeEach(() -> {
          subject = UserCredential.createNewVersion(
              NO_EXISTING_CREDENTIAL,
              CREDENTIAL_NAME,
              new UserSetRequestFields()
                  .setPassword(USER_PASSWORD)
                  .setUsername(USERNAME),
              encryptor,
              Arrays.asList(
                  new AccessControlEntry("test-user", Arrays.asList(READ, WRITE))
              ));
        });

        it("should create new credential with name", () -> {
          assertThat(subject.getCredentialName().getName(), equalTo(CREDENTIAL_NAME));
        });

        it("should set encryptor", () -> {
          Field encryptorField = ReflectionUtils.findField(UserCredential.class, "encryptor");
          ReflectionUtils.makeAccessible(encryptorField);
          Encryptor actualEncryptor = (Encryptor) encryptorField.get(subject);
          assertThat(actualEncryptor, equalTo(encryptor));
        });

        it("should copy request fields", () -> {
          verify(encryptor).encrypt(USER_PASSWORD);
          assertThat(subject.getUsername(), equalTo(USERNAME));
        });

        it("should set access control entries", () -> {
          AccessEntryData expectedAce = new AccessEntryData(
              subject.getCredentialName(), "test-user", Arrays.asList(READ, WRITE));
          assertThat(subject.getCredentialName().getAccessControlList(),
              containsInAnyOrder(
                  samePropertyValuesAs(expectedAce)
              ));
        });
      });
    });

    describe("#rotate", () -> {
      beforeEach(() -> {
        UUID oldEncryptionKeyUuid = UUID.randomUUID();
        byte[] oldEncryptedPassword = "old-encrypted-password".getBytes();
        byte[] oldNonce = "old-nonce".getBytes();
        userCredentialData = new UserCredentialData(CREDENTIAL_NAME)
            .setEncryptionKeyUuid(oldEncryptionKeyUuid)
            .setEncryptedValue(oldEncryptedPassword)
            .setNonce(oldNonce);
        subject = new UserCredential(userCredentialData)
            .setEncryptor(encryptor);
        when(encryptor.decrypt(
            eq(oldEncryptionKeyUuid), eq(oldEncryptedPassword), eq(oldNonce)))
            .thenReturn(USER_PASSWORD);
        when(encryptor.encrypt(eq(USER_PASSWORD)))
            .thenReturn(new Encryption(ENCRYPTION_KEY_UUID, ENCRYPTED_PASSWORD, NONCE));
      });

      it("should re-encrypt the password with the new encryption key", () -> {
        subject.rotate();
        verify(encryptor).decrypt(any(), any(), any());
        verify(encryptor).encrypt(USER_PASSWORD);

        assertThat(userCredentialData.getEncryptionKeyUuid(), equalTo(ENCRYPTION_KEY_UUID));
        assertThat(userCredentialData.getEncryptedValue(), equalTo(ENCRYPTED_PASSWORD));
        assertThat(userCredentialData.getNonce(), equalTo(NONCE));
      });
    });
  }
}
