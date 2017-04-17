package io.pivotal.security.domain;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.NamedUserSecretData;
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
public class NamedUserSecretTest {
  private NamedUserSecret subject;
  private Encryptor encryptor;
  private final String SECRET_NAME = "/test/user";
  private final String USER_PASSWORD = "test-user-password";
  private final String USERNAME = "test-username";
  private final UUID ENCRYPTION_KEY_UUID = UUID.randomUUID();
  private final byte[] ENCRYPTED_PASSWORD = "encrypted-user-password".getBytes();
  private final byte[] NONCE = "user-NONCE".getBytes();
  private NamedUserSecret NO_EXISTING_SECRET = null;
  private NamedUserSecretData userSecretData;

  {
    beforeEach(() -> {
      encryptor = mock(Encryptor.class);
    });

    describe("#getSecretType", () -> {
      it("should return user type", () -> {
        subject = new NamedUserSecret();
        assertThat(subject.getSecretType(), equalTo("user"));
      });
    });

    describe("#getUsername", () -> {
      it("gets username from the delegate", () -> {
        subject = new NamedUserSecret(
            new NamedUserSecretData(SECRET_NAME).setUsername("test-user"));
        assertThat(subject.getUsername(), equalTo("test-user"));
      });
    });

    describe("#setUsername", () -> {
      it("sets username on the delegate", () -> {
        NamedUserSecretData delegate = new NamedUserSecretData(SECRET_NAME);
        subject = new NamedUserSecret(delegate);
        subject.setUsername("test-user");
        assertThat(delegate.getUsername(), equalTo("test-user"));
      });
    });

    describe("#getPassword", () -> {
      beforeEach(() -> {
        when(encryptor.decrypt(
            eq(ENCRYPTION_KEY_UUID), eq(ENCRYPTED_PASSWORD), eq(NONCE)))
            .thenReturn(USER_PASSWORD);
        userSecretData = new NamedUserSecretData()
            .setEncryptedValue(ENCRYPTED_PASSWORD)
            .setNonce(NONCE)
            .setEncryptionKeyUuid(ENCRYPTION_KEY_UUID);
        subject = new NamedUserSecret(userSecretData)
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
        userSecretData = new NamedUserSecretData(SECRET_NAME);
        subject = new NamedUserSecret(userSecretData)
            .setEncryptor(encryptor);
        subject.setPassword(USER_PASSWORD);
      });

      it("should encrypt provided password", () -> {
        verify(encryptor, times(1)).encrypt(eq(USER_PASSWORD));
      });

      it("sets encryption key uuid, encrypted value and the nonce on the delegate", () -> {
        subject.setPassword(USER_PASSWORD);

        assertThat(userSecretData.getEncryptionKeyUuid(), equalTo(ENCRYPTION_KEY_UUID));
        assertThat(userSecretData.getEncryptedValue(), equalTo(ENCRYPTED_PASSWORD));
        assertThat(userSecretData.getNonce(), equalTo(NONCE));
      });
    });

    describe("create new version", () -> {
      beforeEach(() -> {
        when(encryptor.encrypt(eq(USER_PASSWORD)))
            .thenReturn(new Encryption(ENCRYPTION_KEY_UUID, ENCRYPTED_PASSWORD, NONCE));
      });

      describe("when there is an existing secret", () -> {
        it("should set name reference from existing secret if present", () -> {
          NamedUserSecretData existingUserSecretData = new NamedUserSecretData(SECRET_NAME);
          subject = NamedUserSecret.createNewVersion(
              new NamedUserSecret(existingUserSecretData),
              SECRET_NAME,
              new UserSetRequestFields()
                  .setPassword(USER_PASSWORD)
                  .setUsername(USERNAME),
              encryptor,
              newArrayList());

          assertThat(subject.getSecretName(), equalTo(existingUserSecretData.getSecretName()));
        });
      });

      describe("when there is no existing secret", () -> {
        beforeEach(() -> {
          subject = NamedUserSecret.createNewVersion(
              NO_EXISTING_SECRET,
              SECRET_NAME,
              new UserSetRequestFields()
                  .setPassword(USER_PASSWORD)
                  .setUsername(USERNAME),
              encryptor,
              Arrays.asList(
                  new AccessControlEntry("test-user", Arrays.asList(READ, WRITE))
              ));
        });

        it("should create new secret with name", () -> {
          assertThat(subject.getSecretName().getName(), equalTo(SECRET_NAME));
        });

        it("should set encryptor", () -> {
          Field encryptorField = ReflectionUtils.findField(NamedUserSecret.class, "encryptor");
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
              subject.getSecretName(), "test-user", Arrays.asList(READ, WRITE));
          assertThat(subject.getSecretName().getAccessControlList(),
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
        userSecretData = new NamedUserSecretData(SECRET_NAME)
            .setEncryptionKeyUuid(oldEncryptionKeyUuid)
            .setEncryptedValue(oldEncryptedPassword)
            .setNonce(oldNonce);
        subject = new NamedUserSecret(userSecretData)
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

        assertThat(userSecretData.getEncryptionKeyUuid(), equalTo(ENCRYPTION_KEY_UUID));
        assertThat(userSecretData.getEncryptedValue(), equalTo(ENCRYPTED_PASSWORD));
        assertThat(userSecretData.getNonce(), equalTo(NONCE));
      });
    });
  }
}
