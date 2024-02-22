package org.cloudfoundry.credhub.services;

import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.util.concurrent.TimeUnit;

import javax.crypto.AEADBadTagException;
import javax.net.ssl.SSLException;

import com.google.protobuf.ByteString;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.channel.Channel;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.epoll.Epoll;
import io.netty.channel.epoll.EpollDomainSocketChannel;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.kqueue.KQueue;
import io.netty.channel.kqueue.KQueueDomainSocketChannel;
import io.netty.channel.kqueue.KQueueEventLoopGroup;
import io.netty.channel.unix.DomainSocketAddress;
import io.netty.handler.ssl.SslContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.config.EncryptionConfiguration;
import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.services.grpc.DecryptRequest;
import org.cloudfoundry.credhub.services.grpc.DecryptResponse;
import org.cloudfoundry.credhub.services.grpc.EncryptRequest;
import org.cloudfoundry.credhub.services.grpc.EncryptResponse;
import org.cloudfoundry.credhub.services.grpc.KeyManagementServiceGrpc;

import static java.nio.charset.StandardCharsets.UTF_8;

public class KMSEncryptionProvider implements EncryptionProvider {
  private static final Logger LOGGER = LogManager.getLogger(KMSEncryptionProvider.class.getName());
  private static final String CHARSET = "UTF-8";
  private final KeyManagementServiceGrpc.KeyManagementServiceBlockingStub blockingStub;
  private EventLoopGroup group;
  private Class<? extends Channel> channelType;

  public KMSEncryptionProvider(final EncryptionConfiguration configuration) {
    super();

    setChannelInfo();

    SslContext sslContext;
    try {
      sslContext = GrpcSslContexts.forClient()
        .trustManager(new ByteArrayInputStream(configuration.getCa().getBytes(UTF_8)))
        .build();
    } catch (SSLException e) {
      throw new RuntimeException(e);
    }

    final long KEEPALIVE_TIMEOUT_NANOS = TimeUnit.SECONDS.toNanos(20L);
    blockingStub = KeyManagementServiceGrpc.newBlockingStub(
      NettyChannelBuilder.forAddress(new DomainSocketAddress(configuration.getEndpoint()))
        .eventLoopGroup(group)
        .channelType(channelType)
        .keepAliveTime(KEEPALIVE_TIMEOUT_NANOS, TimeUnit.NANOSECONDS)
        .useTransportSecurity()
        .sslContext(sslContext)
        .overrideAuthority(configuration.getHost())
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

  private void setChannelInfo() {
    if (Epoll.isAvailable()) {
      this.group = new EpollEventLoopGroup();
      this.channelType = EpollDomainSocketChannel.class;
      LOGGER.info("Using epoll for Netty transport.");
    } else {
      if (!KQueue.isAvailable()) {
        throw new RuntimeException("Unsupported OS '" + System.getProperty("os.name") + "', only Unix and Mac are supported");
      }

      this.group = new KQueueEventLoopGroup();
      this.channelType = KQueueDomainSocketChannel.class;
      LOGGER.info("Using KQueue for Netty transport.");
    }

  }
}
