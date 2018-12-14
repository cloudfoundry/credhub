package org.cloudfoundry.credhub;

import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.data.ExpiryDateMigration;

@Component
public class ApplicationStartup implements ApplicationListener<ApplicationReadyEvent> {

  private final ExpiryDateMigration expiryDateMigration;

  public ApplicationStartup(final ExpiryDateMigration expiryDateMigration) {
    super();
    this.expiryDateMigration = expiryDateMigration;
  }

  @Override
  public void onApplicationEvent(final ApplicationReadyEvent event) {
    expiryDateMigration.migrate();
  }
}
