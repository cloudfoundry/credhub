package org.cloudfoundry.credhub.config

import org.springframework.boot.jdbc.DataSourceBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.context.annotation.Profile
import org.springframework.core.env.Environment
import org.springframework.jdbc.core.JdbcTemplate
import java.sql.ResultSet
import javax.sql.DataSource

@Profile("unit-test-aurora")
@Configuration
class ParallelAuroraTestDataSourceConfiguration(
    private val environment: Environment,
) {
    private fun getGradleWorkerId(): String = System.getProperty("org.gradle.test.worker")

    private fun createTestDatabaseForWorker(workerId: String) {
        val workerDatabaseName = "credhub_test_$workerId"
        val baseUrl = environment.getProperty("spring.datasource.url", "jdbc:aws-wrapper:mariadb://localhost:3306/credhub_test")
        val username = environment.getProperty("spring.datasource.username", "root")
        val password = environment.getProperty("spring.datasource.password", "")

        // Extract base URL without database name
        val urlWithoutDb = baseUrl.substringBeforeLast("/")

        val tempDataSource =
            DataSourceBuilder
                .create()
                .url(urlWithoutDb)
                .username(username)
                .password(password)
                .build()

        val jdbcTemplate = JdbcTemplate(tempDataSource)
        val noDb =
            jdbcTemplate
                .query(
                    "SELECT 1 from INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = ?;",
                    { rs: ResultSet, _: Int -> rs.getBoolean(1) },
                    workerDatabaseName,
                ).isEmpty()

        if (noDb) {
            jdbcTemplate.execute("CREATE DATABASE $workerDatabaseName")
        }

        tempDataSource.connection.close()
    }

    @Primary
    @Bean(name = ["dataSource"])
    fun getParallelTestDataSource(): DataSource {
        val workerId = getGradleWorkerId()

        createTestDatabaseForWorker(workerId)

        val baseUrl = environment.getProperty("spring.datasource.url", "jdbc:aws-wrapper:mariadb://localhost:3306/credhub_test")
        val username = environment.getProperty("spring.datasource.username", "root")
        val password = environment.getProperty("spring.datasource.password", "")

        // Extract base URL without database name and append worker-specific database
        val urlWithoutDb = baseUrl.substringBeforeLast("/")
        val urlWithWorkerDb = "$urlWithoutDb/credhub_test_$workerId"

        val dataSource =
            DataSourceBuilder
                .create()
                .url(urlWithWorkerDb)
                .username(username)
                .password(password)
                .build()

        return dataSource
    }
}
