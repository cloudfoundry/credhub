package org.cloudfoundry.credhub.data;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.h2.tools.TriggerAdapter;

/**
 * H2 trigger for password_credential or user_credential record deletion
 */
public class PasswordOrUserCredentialDeleteTrigger extends TriggerAdapter {
    @Override
    public void fire(Connection conn, ResultSet oldRow, ResultSet newRow)
            throws SQLException {
        try (PreparedStatement stmt = conn.prepareStatement(
                "DELETE FROM encrypted_value WHERE uuid = ?")) {
            stmt.setObject(1, oldRow.getObject("password_parameters_uuid"));
            stmt.executeUpdate();
        }
    }
}
