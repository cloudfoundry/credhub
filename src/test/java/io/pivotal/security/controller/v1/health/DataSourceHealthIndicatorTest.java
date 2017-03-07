package io.pivotal.security.controller.v1.health;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.boot.autoconfigure.jdbc.EmbeddedDatabaseConnection;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

import javax.sql.DataSource;
import java.sql.Connection;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;


public class DataSourceHealthIndicatorTest {
  private DataSourceHealthIndicator subject;
  private Map<String, DataSource> dataSources;

  @Before
  public void setUp() {
    dataSources = new HashMap<>();
    dataSources.put("dataSource", mock(DataSource.class));
    this.subject = new DataSourceHealthIndicator(dataSources);
    addSingleConnectionSourceToDataSources();
  }

  @After
  public void tearDown() {
    SingleConnectionDataSource dataSource = (SingleConnectionDataSource) dataSources.get("dataSource");
    if (dataSource != null) {
      dataSource.destroy();
    }
  }

  @Test
  public void healthyDatabaseHasHealthyStatus() throws Exception {
    Health.Builder builder = new Health.Builder();
    subject.checkHealth(builder);
    Health build = builder.build();
    assertEquals(build.getStatus(), Status.UP);
  }

  @Test(expected = RuntimeException.class)
  public void nullDatabaseThrows() throws Exception {
    dataSources.put("dataSource", null);
    Health.Builder builder = new Health.Builder();
    subject.checkHealth(builder);
    fail("expected exception");
  }

  @Test(expected = RuntimeException.class)
  public void unhealthyDatabaseThrows() throws Exception {
    DataSource dataSource = mock(DataSource.class);
    Connection connection = mock(Connection.class);
    given(connection.getMetaData())
        .willReturn(dataSource.getConnection().getMetaData());
    given(dataSource.getConnection()).willThrow(RuntimeException.class);
    dataSources.put("dataSource", null);
    Health.Builder builder = new Health.Builder();
    subject.checkHealth(builder);
    fail("expected exception");
  }

  private void addSingleConnectionSourceToDataSources() {
    EmbeddedDatabaseConnection db = EmbeddedDatabaseConnection.H2;
    SingleConnectionDataSource dataSource = new SingleConnectionDataSource(db.getUrl(),
        "sa", "", false);
    dataSource.setDriverClassName(db.getDriverClassName());
    dataSources.put("dataSource", dataSource);
  }

  public void setDataSources(Map<String, DataSource> dataSources) {
    this.dataSources = dataSources;
  }
}
