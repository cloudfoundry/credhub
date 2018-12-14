package org.cloudfoundry.credhub.service;

import java.nio.charset.Charset;
import java.util.concurrent.TimeUnit;

import javax.crypto.AEADBadTagException;

import com.google.protobuf.ByteString;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.NegotiationType;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.channel.epoll.EpollDomainSocketChannel;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.unix.DomainSocketAddress;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.config.EncryptionConfiguration;
import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.service.grpc.DecryptRequest;
import org.cloudfoundry.credhub.service.grpc.DecryptResponse;
import org.cloudfoundry.credhub.service.grpc.EncryptRequest;
import org.cloudfoundry.credhub.service.grpc.EncryptResponse;
import org.cloudfoundry.credhub.service.grpc.KeyManagementServiceGrpc;

import static io.grpc.internal.GrpcUtil.DEFAULT_KEEPALIVE_TIME_NANOS;

public class ExternalEncryptionProvider implements EncryptionProvider {
  private static final Logger LOGGER = LogManager.getLogger(ExternalEncryptionProvider.class.getName());
  private static final String CHARSET = "UTF-8";
  private final KeyManagementServiceGrpc.KeyManagementServiceBlockingStub blockingStub;

  public ExternalEncryptionProvider(final EncryptionConfiguration configuration) {
    super();
    blockingStub = KeyManagementServiceGrpc.newBlockingStub(
      NettyChannelBuilder.forAddress(new DomainSocketAddress(configuration.getEndpoint()))
        .eventLoopGroup(new EpollEventLoopGroup())
        .channelType(EpollDomainSocketChannel.class)
        .negotiationType(NegotiationType.PLAINTEXT)
        .keepAliveTime(DEFAULT_KEEPALIVE_TIME_NANOS, TimeUnit.NANOSECONDS)
        .build());
  }

  @Override
  public EncryptedValue encrypt(final EncryptionKey key, final String value) {
    final EncryptRequest request = EncryptRequest.newBuilder().setPlain(ByteString.copyFrom(value, Charset.forName(CHARSET))).build();
    final EncryptResponse response;
    try {
      response = blockingStub.encrypt(request);
    } catch (final StatusRuntimeException e) {
      LOGGER.error("Error for request: " + request.getPlain(), e);
      throw e;
    }
    return new EncryptedValue(key.getUuid(), response.getCipher().toByteArray(), new byte[]{});
  }


  @Override
  public String decrypt(final EncryptionKey key, final byte[] encryptedValue, final byte[] nonce) throws Exception {
    final DecryptRequest request = DecryptRequest.newBuilder().setCipher(ByteString.copyFrom(encryptedValue)).build();
    final DecryptResponse response;
    try {
      response = blockingStub.decrypt(request);
    } catch (final StatusRuntimeException e) {
      if (e.getStatus().getCode() == Status.Code.INVALID_ARGUMENT) {
        throw new AEADBadTagException(e.getMessage());
      }
      LOGGER.error("Error for request: " + request.getCipher(), e);
      throw e;
    }

    return response.getPlain().toString(CHARSET);
  }

  @Override
  public KeyProxy createKeyProxy(final EncryptionKeyMetadata encryptionKeyMetadata) {
    return new ExternalKeyProxy(encryptionKeyMetadata, this);
  }
}
