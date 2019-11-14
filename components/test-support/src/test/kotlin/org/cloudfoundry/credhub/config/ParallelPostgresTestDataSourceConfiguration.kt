package org.cloudfoundry.credhub.config

import org.springframework.boot.jdbc.DataSourceBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.context.annotation.Profile
import org.springframework.jdbc.core.JdbcTemplate
import java.sql.ResultSet
import javax.sql.DataSource

@Profile("unit-test-postgres")
@Configuration
class ParallelPostgresTestDataSourceConfiguration {

    private fun getGradleWorkerId(): String {
        return System.getProperty("org.gradle.test.worker")
    }

    private fun createTestDatabaseForWorker(workerId: String) {

        val workerDatabaseName = "credhub_test_$workerId"

        val tempDataSource = DataSourceBuilder
            .create()
            .url("jdbc:postgresql://localhost:5432/credhub_test?user=pivotal")
            .build()

        val jdbcTemplate = JdbcTemplate(tempDataSource)

        val doesDatabaseExist = jdbcTemplate.query(
            "SELECT 1 FROM pg_database WHERE datname = ?;",
            arrayOf(workerDatabaseName),
            { rs: ResultSet, _: Int -> rs.getBoolean(1) }
        ).size == 1

        if (!doesDatabaseExist) {
            jdbcTemplate.execute("CREATE DATABASE $workerDatabaseName")
        }

        tempDataSource.connection.close()
    }

    @Primary
    @Bean(name = ["dataSource"])
    fun getParallelTestDataSource(): DataSource {

        val workerId = getGradleWorkerId()

        createTestDatabaseForWorker(workerId)

        val dataSource = DataSourceBuilder.create()
            .url("jdbc:postgresql://localhost:5432/credhub_test_$workerId?user=pivotal")
            .build()

        return dataSource
    }
}
