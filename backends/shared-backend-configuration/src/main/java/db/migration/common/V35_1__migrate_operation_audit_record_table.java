package db.migration.common;

import java.sql.Types;
import java.util.List;

import org.springframework.jdbc.core.JdbcTemplate;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.flywaydb.core.api.migration.spring.SpringJdbcMigration;

import static org.cloudfoundry.credhub.utils.UuidUtil.makeUuid;

@SuppressWarnings("unused")
public class V35_1__migrate_operation_audit_record_table implements SpringJdbcMigration {

  @SuppressFBWarnings(
    value = "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE",
    justification = "The database will definitely exist"
  )
  @Override
  public void migrate(final JdbcTemplate jdbcTemplate) throws Exception {
    final String databaseName = jdbcTemplate
      .getDataSource()
      .getConnection()
      .getMetaData()
      .getDatabaseProductName()
      .toLowerCase();

    final List<Long> operationAuditRecordIds = jdbcTemplate.queryForList("select id from operation_audit_record", Long.class);

    for (final Long id: operationAuditRecordIds) {
      final Object requestUuid = makeUuid(databaseName);
      final Object eventUuid = makeUuid(databaseName);

      jdbcTemplate.update(
          "insert into request_audit_record (" +
                "uuid," +
                "host_name," +
                "now," +
                "path," +
                "requester_ip," +
                "auth_valid_from," +
                "auth_valid_until," +
                "uaa_url," +
                "user_id," +
                "user_name," +
                "x_forwarded_for," +
                "scope," +
                "grant_type," +
                "client_id," +
                "method," +
                "status_code," +
                "query_parameters," +
                "auth_method" +
              ") select " +
                "?," +
                "record.host_name," +
                "record.now," +
                "record.path," +
                "record.requester_ip," +
                "record.auth_valid_from," +
                "record.auth_valid_until," +
                "record.uaa_url," +
                "record.user_id," +
                "record.user_name," +
                "record.x_forwarded_for," +
                "record.scope," +
                "record.grant_type," +
                "record.client_id," +
                "record.method," +
                "record.status_code," +
                "record.query_parameters," +
                "record.auth_method " +
              "from operation_audit_record " +
                "as record " +
                "where id = ?",
          new Object[]{requestUuid, id},
          new int[]{Types.VARBINARY, Types.BIGINT}
      );

      jdbcTemplate.update(
          "insert into event_audit_record (" +
                "uuid," +
                "request_uuid," +
                "now," +
                "operation," +
                "credential_name," +
                "actor," +
                "success" +
              ") select " +
                "?," +
                "?," +
                "record.now," +
                "record.operation," +
                "record.credential_name," +
                "null," +
                "record.success " +
              "from operation_audit_record " +
                "as record " +
                "where id = ?",
          new Object[]{eventUuid, requestUuid, id},
          new int[]{Types.VARBINARY, Types.VARBINARY, Types.BIGINT}
      );
    }
  }
}
