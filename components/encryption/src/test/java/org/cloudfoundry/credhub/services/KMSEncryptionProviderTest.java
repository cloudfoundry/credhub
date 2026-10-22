package org.cloudfoundry.credhub.services;

import java.io.PrintWriter;
import java.io.StringWriter;

import javax.crypto.AEADBadTagException;

import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.test.util.ReflectionTestUtils;

import io.grpc.Metadata;
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
  @EnumSource(value = Status.Code.class, names = "OK", mode = EnumSource.Mode.EXCLUDE)
  public void encryptFailureLogsOnlySafeStatus(final Status.Code code, final CapturedOutput output) {
    final String secret = "plaintext-credential-secret";
    final Metadata trailers = new Metadata();
    trailers.put(Metadata.Key.of("backend-error", Metadata.ASCII_STRING_MARSHALLER), secret);
    final StatusRuntimeException failure = Status.fromCode(code)
      .withDescription("backend echoed " + secret)
      .withCause(new IllegalStateException("cause containing " + secret))
      .asRuntimeException(trailers);
    when(blockingStub.encrypt(any(EncryptRequest.class))).thenThrow(failure);

    final StatusRuntimeException thrown = assertThrows(StatusRuntimeException.class, () -> subject.encrypt(null, secret));
    assertSanitizedException(thrown, code, "KMS encryption failed", secret);

    assertThat(output.getAll()).contains("KMS encryption failed with status " + code.name())
      .doesNotContain(secret, "ByteString", "backend echoed", "cause containing");
  }

  @ParameterizedTest
  @EnumSource(value = Status.Code.class, names = {"OK", "INVALID_ARGUMENT", }, mode = EnumSource.Mode.EXCLUDE)
  public void decryptFailureLogsOnlySafeStatus(final Status.Code code, final CapturedOutput output) {
    final String ciphertext = "sensitive-ciphertext";
    final String secret = "plaintext-from-backend";
    final Metadata trailers = new Metadata();
    trailers.put(Metadata.Key.of("backend-error", Metadata.ASCII_STRING_MARSHALLER), secret);
    final StatusRuntimeException failure = Status.fromCode(code)
      .withDescription("backend echoed " + secret)
      .withCause(new IllegalStateException("cause containing " + secret))
      .asRuntimeException(trailers);
    when(blockingStub.decrypt(any(DecryptRequest.class))).thenThrow(failure);

    final StatusRuntimeException thrown = assertThrows(StatusRuntimeException.class,
      () -> subject.decrypt(null, ciphertext.getBytes(UTF_8), new byte[]{}));
    assertSanitizedException(thrown, code, "KMS decryption failed", secret);
    assertThat(thrown).hasStackTraceContaining("KMS decryption failed").hasMessageNotContaining(ciphertext);

    assertThat(output.getAll()).contains("KMS decryption failed with status " + code.name())
      .doesNotContain(ciphertext, secret, "ByteString", "backend echoed", "cause containing");
  }

  @Test
  public void decryptInvalidArgumentStillThrowsBadTagWithoutLogging(final CapturedOutput output) {
    final String secret = "backend-echoed-secret";
    when(blockingStub.decrypt(any(DecryptRequest.class)))
      .thenThrow(Status.INVALID_ARGUMENT.withDescription(secret)
        .withCause(new IllegalStateException(secret)).asRuntimeException());

    final AEADBadTagException thrown = assertThrows(AEADBadTagException.class,
      () -> subject.decrypt(null, "ciphertext".getBytes(UTF_8), new byte[]{}));
    assertThat(thrown).hasMessage("KMS decryption failed: invalid ciphertext").hasNoCause();
    assertThat(renderWrappedException(thrown)).doesNotContain(secret);

    assertThat(output.getAll()).doesNotContain(secret, "ciphertext", "KMS decryption failed");
  }

  private static void assertSanitizedException(final StatusRuntimeException thrown, final Status.Code code,
                                             final String description, final String secret) {
    assertThat(thrown.getStatus().getCode()).isEqualTo(code);
    assertThat(thrown.getStatus().getDescription()).isEqualTo(description);
    assertThat(thrown.getStatus().getCause()).isNull();
    assertThat(thrown.getTrailers()).isNull();
    assertThat(thrown).hasNoCause();
    assertThat(renderWrappedException(thrown)).doesNotContain(secret, "backend echoed", "cause containing");
  }

  private static String renderWrappedException(final Exception exception) {
    final StringWriter output = new StringWriter();
    // DefaultEncryptor wraps the exception before the HTTP handler logs it.
    new RuntimeException(exception).printStackTrace(new PrintWriter(output));
    return output.toString();
  }
}
