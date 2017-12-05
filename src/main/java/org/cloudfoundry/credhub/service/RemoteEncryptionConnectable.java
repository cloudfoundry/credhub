package org.cloudfoundry.credhub.service;

interface RemoteEncryptionConnectable {

  void reconnect(Exception reasonForReconnect) throws Exception;
}
