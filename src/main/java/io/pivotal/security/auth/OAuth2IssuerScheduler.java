package io.pivotal.security.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
@Profile({"prod", "dev"})
public class OAuth2IssuerScheduler {
  private OAuth2IssuerServiceImpl oAuth2IssuerService;

  @Autowired
  OAuth2IssuerScheduler(OAuth2IssuerServiceImpl oAuth2IssuerService) {
    this.oAuth2IssuerService = oAuth2IssuerService;
  }

  @EventListener(ContextRefreshedEvent.class)
  private void refreshIssuer() {
    oAuth2IssuerService.fetchIssuer();
  }
}
