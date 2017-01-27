package io.pivotal.security.service;

interface RemoteEncryptionConnectable {
  void reconnect(Exception originalException) throws Exception;
}
