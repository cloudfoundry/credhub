package org.cloudfoundry.credhub.config;

import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.data.PermissionData;
import org.cloudfoundry.credhub.repositories.PermissionRepository;
import org.cloudfoundry.credhub.repositories.StubPermissionRepository;
import org.cloudfoundry.credhub.utils.StringUtil;

import static com.google.common.collect.Lists.newArrayList;

@Profile("stub-repositories")
@Configuration
public class StubRepositoryConfiguration {

  @Bean
  public PermissionRepository getStubPermissionRepository() {

    final StubPermissionRepository stubPermissionRepository = new StubPermissionRepository();

    final PermissionData permissionData = new PermissionData(
      "/some-path",
      "uaa-client:user-a",
      newArrayList(
        PermissionOperation.READ,
        PermissionOperation.WRITE
      )
    );

    permissionData.setUuid(UUID.nameUUIDFromBytes("some-permission-uuid".getBytes(StringUtil.UTF_8)));

    stubPermissionRepository.setReturn_findByPathAndAnchor(permissionData);

    return stubPermissionRepository;
  }
}
