package io.pivotal.security.controller.v1.health;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.util.Map;

import static com.google.common.collect.ImmutableMap.of;

@Controller
public class HealthController {
  private final DataSourceHealthIndicator dataSourceHealthIndicator;

  @Autowired
  HealthController(DataSourceHealthIndicator dataSourceHealthIndicator) {
    this.dataSourceHealthIndicator = dataSourceHealthIndicator;
  }

  @RequestMapping(value = "/health", method = RequestMethod.GET)
  public ResponseEntity<Map> getHealth() {
    try {
      Health health = health();
      return new ResponseEntity<>(of("db", health), HttpStatus.OK);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private Health health() {
    Health.Builder builder = new Health.Builder();
    try {
      dataSourceHealthIndicator.checkHealth(builder);
    }
    catch (Exception ex) {
      builder.down(ex);
    }
    return builder.build();
  }
}
