package org.cloudfoundry.credhub.handlers;

import java.sql.SQLException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.JdbcUtils;
import org.springframework.jdbc.support.MetaDataAccessException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.certificates.DefaultCertificatesHandler;
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver;
import org.cloudfoundry.credhub.views.CertificateCredentialsView;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
public class DefaultCertificatesHandlerIntegrationTest {
    @Autowired
    private DefaultCertificatesHandler defaultCertificatesHandler;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private Environment environment;

    @Before
    public void setUp() throws Exception {
        Assume.assumeTrue(
                "Test is for Postgres only",
                environment.acceptsProfiles(Profiles.of("unit-test-postgres")));
        Assume.assumeTrue("Test is for Postgres version higher than 10 because the SQL in this test is incompatible with postgres 10",
                getDatabaseMajorVersion(jdbcTemplate) > 10);


        insertTestCredentialsIntoPostgres(65535 + 1);
    }

    private int getDatabaseMajorVersion(JdbcTemplate jdbcTemplate)
            throws SQLException, MetaDataAccessException {
        try {
            return JdbcUtils.extractDatabaseMetaData(
                    jdbcTemplate.getDataSource(), dbmd -> dbmd).getDatabaseMajorVersion();
        } catch (MetaDataAccessException ex) {
            throw ex;
        }
    }

    // As of Postgres JDBC Driver 42.4.0, the driver supports up to 65535 (inclusive) parameters
    // See: https://jdbc.postgresql.org/changelogs/2022-06-09-42.4.0-release/
    @Test
    public void handleGetAllRequest_65536Certs_doesNotCrash() {
        CertificateCredentialsView certificateCredentialsView = defaultCertificatesHandler.handleGetAllRequest();
        assertThat(certificateCredentialsView, is(notNullValue()));
    }

    private void insertTestCredentialsIntoPostgres(int count) {
        jdbcTemplate.update(
                "INSERT INTO credential (uuid, name, checksum) " +
                        "SELECT uuid, name, uuid as checksum FROM (\n" +
                        "    SELECT gen_random_uuid() as uuid, concat('certificate-', id) as name\n" +
                        "                            FROM generate_series(1, ?) as id) foo", count);

        jdbcTemplate.update(
                "INSERT INTO credential_version (type, uuid, version_created_at, credential_uuid) " +
                        "SELECT 'foo', uuid, 0, uuid from credential");

        jdbcTemplate.update(
                "INSERT INTO certificate_credential (uuid, transitional) " +
                        "SELECT uuid, FALSE FROM credential");
    }
}
