package org.cloudfoundry.credhub;

import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.data.CertificateMigration;

@Component
public class ApplicationStartup implements ApplicationListener<ApplicationReadyEvent> {

  private final CertificateMigration certificateMigration;

  public ApplicationStartup(final CertificateMigration certificateMigration) {
    super();
    this.certificateMigration = certificateMigration;
  }

  @Override
  public void onApplicationEvent(final ApplicationReadyEvent event) {
    certificateMigration.migrate();
  }
}
