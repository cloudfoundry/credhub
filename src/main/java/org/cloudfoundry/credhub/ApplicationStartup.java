package org.cloudfoundry.credhub;

import org.cloudfoundry.credhub.data.ExpiryDateMigration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

@Component
public class ApplicationStartup implements ApplicationListener<ApplicationReadyEvent> {
    @Autowired
    private ExpiryDateMigration expiryDateMigration;

    @Override
    public void onApplicationEvent(final ApplicationReadyEvent event) {
        expiryDateMigration.migrate();
    }
}
