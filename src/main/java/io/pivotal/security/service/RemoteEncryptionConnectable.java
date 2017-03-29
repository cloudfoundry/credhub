package io.pivotal.security.service;

interface RemoteEncryptionConnectable {

  void reconnect(Exception reasonForReconnect) throws Exception;
}
