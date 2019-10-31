package org.cloudfoundry.credhub.config

import org.springframework.boot.jdbc.DataSourceBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.context.annotation.Profile
import org.springframework.jdbc.core.JdbcTemplate
import java.sql.ResultSet
import javax.sql.DataSource

@Profile("unit-test-mysql")
@Configuration
class ParallelMysqlTestDataSourceConfiguration {

    private fun getGradleWorkerId(): String {
        return System.getProperty("org.gradle.test.worker")
    }

    private fun createTestDatabaseForWorker(workerId: String) {

        val workerDatabaseName = "credhub_test_$workerId"

        val tempDataSource = DataSourceBuilder
            .create()
            .url("jdbc:mariadb://localhost:3306?user=root")
            .build()

        val jdbcTemplate = JdbcTemplate(tempDataSource)

        val doesDatabaseExist = jdbcTemplate.query(
            "SELECT 1 from INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = ?;",
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
            .url("jdbc:mariadb://localhost:3306/credhub_test_$workerId?user=root")
            .build()

        return dataSource
    }
}
