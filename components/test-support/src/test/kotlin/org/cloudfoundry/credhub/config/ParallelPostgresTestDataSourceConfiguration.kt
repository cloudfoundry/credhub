package org.cloudfoundry.credhub.config

import com.zaxxer.hikari.HikariDataSource
import org.springframework.boot.jdbc.DataSourceBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.context.annotation.Profile
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.DriverManagerDataSource
import java.sql.ResultSet
import javax.sql.DataSource

@Profile("unit-test-postgres")
@Configuration
class ParallelPostgresTestDataSourceConfiguration {
    private fun getGradleWorkerId(): String = System.getProperty("org.gradle.test.worker")

    private fun createTestDatabaseForWorker(workerId: String) {
        val workerDatabaseName = "credhub_test_$workerId"
        val tempDataSource =
            DriverManagerDataSource(
                "jdbc:postgresql://localhost:5432/credhub_test?user=pivotal&connectTimeout=10",
            )

        val jdbcTemplate = JdbcTemplate(tempDataSource)
        val noDb =
            jdbcTemplate
                .query(
                    "SELECT 1 FROM pg_database WHERE datname = ?;",
                    { rs: ResultSet, _: Int -> rs.getBoolean(1) },
                    workerDatabaseName,
                ).isEmpty()
        if (noDb) {
            jdbcTemplate.execute("CREATE DATABASE $workerDatabaseName")
        }
    }

    @Primary
    @Bean(name = ["dataSource"])
    fun getParallelTestDataSource(): DataSource {
        val workerId = getGradleWorkerId()

        createTestDatabaseForWorker(workerId)

        val dataSource =
            DataSourceBuilder
                .create()
                .type(HikariDataSource::class.java)
                .url("jdbc:postgresql://localhost:5432/credhub_test_$workerId?user=pivotal&connectTimeout=10")
                .build()

        dataSource.maximumPoolSize = 5
        dataSource.minimumIdle = 1
        dataSource.connectionInitSql = "SET statement_timeout = '120s'"

        return dataSource
    }
}
