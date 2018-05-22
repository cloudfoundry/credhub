package org.cloudfoundry.credhub.service;

import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NegotiationType;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.config.EncryptionConfiguration;
import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.service.grpc.*;

import java.io.IOException;

public class ExternalEncryptionProvider implements EncryptionProvider {
  private static final Logger logger = LogManager.getLogger(ExternalEncryptionProvider.class.getName());
  private static final String CHARSET = "UTF-8";
  private final EncryptionProviderGrpc.EncryptionProviderBlockingStub blockingStub;

  public ExternalEncryptionProvider(EncryptionConfiguration configuration) throws IOException {
    this(NettyChannelBuilder.forAddress(configuration.getHost(), configuration.getPort())
        .negotiationType(NegotiationType.TLS)
        .sslContext(buildSslContext(configuration.getServerCa(), configuration.getClientCertificate(),
            configuration.getClientKey()))
        .build());
  }

  ExternalEncryptionProvider(ManagedChannel channel) {
    blockingStub = EncryptionProviderGrpc.newBlockingStub(channel);
  }

  @Override
  public EncryptedValue encrypt(EncryptionKey key, String value) {
    EncryptionResponse response = encrypt(key.getEncryptionKeyName(), value);
    return new EncryptedValue(key.getUuid(), response.getData().toByteArray(), response.getNonce().toByteArray());
  }


  @Override
  public String decrypt(EncryptionKey key, byte[] encryptedValue, byte[] nonce) throws Exception {
    DecryptionResponse response = decrypt(new String(encryptedValue, CHARSET), key.getEncryptionKeyName(), new String(nonce, CHARSET));
    return response.getData();
  }

  @Override
  public KeyProxy createKeyProxy(EncryptionKeyMetadata encryptionKeyMetadata) {
    return new ExternalKeyProxy(encryptionKeyMetadata, this);
  }

  private EncryptionResponse encrypt(String keyId, String value) {
    EncryptionRequest request = EncryptionRequest.newBuilder().setData(value).setKey(keyId).build();
    EncryptionResponse response;
    try {
      response = blockingStub.encrypt(request);
    } catch (StatusRuntimeException e) {
      logger.error("Error for request: " + request.getData(), e);
      throw (e);
    }
    return response;
  }

  private DecryptionResponse decrypt(String value, String keyId, String nonce) {
    DecryptionRequest request = DecryptionRequest.newBuilder().
        setData(value).
        setKey(keyId).
        setNonce(nonce).
        build();
    DecryptionResponse response;

    try {
      response = blockingStub.decrypt(request);
    } catch (StatusRuntimeException e) {
      logger.error("Error for request: " + request.getData(), e);
      throw (e);
    }
    return response;
  }

  private static SslContext buildSslContext(String serverCA,
                                            String clientCertificate,
                                            String clientPrivateKey) throws IOException {
    SslContextBuilder builder = GrpcSslContexts.forClient();
    builder.sslProvider(SslProvider.OPENSSL);
    if (serverCA != null) {
      builder.trustManager(IOUtils.toInputStream(serverCA, CHARSET));
    }
    if (clientCertificate != null && clientPrivateKey != null) {
      builder.keyManager(IOUtils.toInputStream(clientCertificate, CHARSET), IOUtils.toInputStream(clientPrivateKey, CHARSET));
    } else {
      throw new RuntimeException("Unable to fetch client certificate or client private key for external provider.");
    }
    return builder.build();
  }

}
