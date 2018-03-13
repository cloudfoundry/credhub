package org.cloudfoundry.credhub.config;

public class EncryptionConfiguration {
  private Integer port;
  private String host, partition, partitionPassword;

  public Integer getPort() {
    return port;
  }

  public void setPort(Integer port) {
    this.port = port;
  }

  public String getHost() {
    return host;
  }

  public void setHost(String host) {
    this.host = host;
  }

  public String getPartition() {
    return partition;
  }

  public void setPartition(String partition) {
    this.partition = partition;
  }

  public String getPartitionPassword() {
    return partitionPassword;
  }

  public void setPartitionPassword(String partitionPassword) {
    this.partitionPassword = partitionPassword;
  }

  @Override
  public String toString() {
    return "EncryptionConfiguration{" +
        "port=" + port +
        ", host='" + host + '\'' +
        ", partition='" + partition + '\'' +
        ", partitionPassword='" + partitionPassword + '\'' +
        '}';
  }
}
