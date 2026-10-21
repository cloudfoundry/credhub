package org.cloudfoundry.credhub.services;

import javax.crypto.AEADBadTagException;

import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.test.util.ReflectionTestUtils;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.cloudfoundry.credhub.services.grpc.DecryptRequest;
import org.cloudfoundry.credhub.services.grpc.EncryptRequest;
import org.cloudfoundry.credhub.services.grpc.KeyManagementServiceGrpc;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(OutputCaptureExtension.class)
public class KMSEncryptionProviderTest {
  private KeyManagementServiceGrpc.KeyManagementServiceBlockingStub blockingStub;
  private KMSEncryptionProvider subject;

  @BeforeEach
  public void setUp() {
    blockingStub = mock(KeyManagementServiceGrpc.KeyManagementServiceBlockingStub.class);
    subject = mock(KMSEncryptionProvider.class, CALLS_REAL_METHODS);
    ReflectionTestUtils.setField(subject, "blockingStub", blockingStub);
  }

  @ParameterizedTest
  @EnumSource(value = Status.Code.class, names = {"UNAVAILABLE", "DEADLINE_EXCEEDED", "INTERNAL", "UNKNOWN", })
  public void encryptFailureLogsOnlySafeStatus(final Status.Code code, final CapturedOutput output) {
    final String secret = "plaintext-credential-secret";
    final StatusRuntimeException failure = Status.fromCode(code)
      .withDescription("backend echoed " + secret)
      .withCause(new IllegalStateException("cause containing " + secret))
      .asRuntimeException();
    when(blockingStub.encrypt(any(EncryptRequest.class))).thenThrow(failure);

    assertSame(failure, assertThrows(StatusRuntimeException.class, () -> subject.encrypt(null, secret)));

    assertThat(output.getAll()).contains("KMS encryption failed with status " + code.name())
      .doesNotContain(secret, "ByteString", "backend echoed", "cause containing");
  }

  @ParameterizedTest
  @EnumSource(value = Status.Code.class, names = {"UNAVAILABLE", "DEADLINE_EXCEEDED", "INTERNAL", "UNKNOWN", })
  public void decryptFailureLogsOnlySafeStatus(final Status.Code code, final CapturedOutput output) {
    final String ciphertext = "sensitive-ciphertext";
    final String secret = "plaintext-from-backend";
    final StatusRuntimeException failure = Status.fromCode(code)
      .withDescription("backend echoed " + secret)
      .withCause(new IllegalStateException("cause containing " + secret))
      .asRuntimeException();
    when(blockingStub.decrypt(any(DecryptRequest.class))).thenThrow(failure);

    assertSame(failure, assertThrows(StatusRuntimeException.class,
      () -> subject.decrypt(null, ciphertext.getBytes(UTF_8), new byte[]{})));

    assertThat(output.getAll()).contains("KMS decryption failed with status " + code.name())
      .doesNotContain(ciphertext, secret, "ByteString", "backend echoed", "cause containing");
  }

  @Test
  public void decryptInvalidArgumentStillThrowsBadTagWithoutLogging(final CapturedOutput output) {
    when(blockingStub.decrypt(any(DecryptRequest.class)))
      .thenThrow(Status.INVALID_ARGUMENT.withDescription("invalid ciphertext").asRuntimeException());

    assertThrows(AEADBadTagException.class,
      () -> subject.decrypt(null, "ciphertext".getBytes(UTF_8), new byte[]{}));

    assertThat(output.getAll()).doesNotContain("ciphertext", "KMS decryption failed");
  }
}
