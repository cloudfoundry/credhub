package org.cloudfoundry.credhub.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnProperty(value = "encryption.provider", havingValue = "hsm")
public class LunaProviderProperties {

  @Value("${hsm.partition}")
  String partitionName;

  @Value("${hsm.partition_password}")
  String partitionPassword;

  public String getPartitionName() {
    return partitionName;
  }

  public String getPartitionPassword() {
    return partitionPassword;
  }
}
