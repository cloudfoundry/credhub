package org.cloudfoundry.credhub.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.StatusRuntimeException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.service.grpc.DecryptionRequest;
import org.cloudfoundry.credhub.service.grpc.DecryptionResponse;
import org.cloudfoundry.credhub.service.grpc.EncryptionProviderGrpc;
import org.cloudfoundry.credhub.service.grpc.EncryptionRequest;
import org.cloudfoundry.credhub.service.grpc.EncryptionResponse;

public class ExternalEncryptionProvider implements EncryptionProvider {
  private static final Logger logger = LogManager.getLogger(ExternalEncryptionProvider.class.getName());
  private static final String CHARSET = "UTF-8";

  private final ObjectMapper objectMapper;
  private final EncryptionProviderGrpc.EncryptionProviderBlockingStub blockingStub;

  public ExternalEncryptionProvider(String host, int port){

    this(ManagedChannelBuilder.forAddress(host, port)
        // Channels are secure by default (via SSL/TLS). For the example we disable TLS to avoid
        // needing certificates.
        .usePlaintext(true)
        .build());
  }

  ExternalEncryptionProvider(ManagedChannel channel){
    blockingStub = EncryptionProviderGrpc.newBlockingStub(channel);
    objectMapper = new ObjectMapper();
  }

  @Override
  public EncryptedValue encrypt(EncryptionKey key, String value) throws Exception {
    EncryptionResponse response = encrypt(key.getEncryptionKeyName(), value);
    return new EncryptedValue(key.getUuid(),response.getData().toByteArray(),response.getNonce().toByteArray());
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

  private EncryptionResponse encrypt(String keyId, String value) throws Exception {
    EncryptionRequest request = EncryptionRequest.newBuilder().setData(value).setKey(keyId).build();
    EncryptionResponse response;
    try {
      response = blockingStub.encrypt(request);
    } catch (StatusRuntimeException e) {
      logger.error("Error for request: " + request.getData(), e);
      throw(e);
    }
    return response;
  }

  private DecryptionResponse decrypt(String value, String keyId, String nonce) throws Exception {
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
      throw(e);
    }
    return response;
  }
}
