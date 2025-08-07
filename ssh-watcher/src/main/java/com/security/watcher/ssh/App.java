package com.security.watcher.ssh;

import java.io.IOException;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public class App {
    public static void main(String[] args) {
        System.out.println("SSH Watcher starting");

        try (Connection conn = SQLiteConnectionManager.getConnection()) {
            if (conn != null) {
                System.out.println("Connected to SQLite.");
                try (Statement stmt = conn.createStatement()) {
                    stmt.executeUpdate("CREATE TABLE IF NOT EXISTS logins (" +
                            "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                            "user TEXT NOT NULL," +
                            "result TEXT NOT NULL," +
                            "method TEXT NOT NULL," +
                            "port INTEGER NOT NULL," +
                            "geoLocation TEXT," +
                            "sourceIP TEXT," +
                            "timestamp TEXT)");
                    stmt.executeUpdate("CREATE TABLE  IF NOT EXISTS suspicious_ips (" +
                            "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                            "source_ip TEXT NOT NULL," +
                            "failed_count INTEGER NOT NULL," +
                            "first_detected TEXT DEFAULT (datetime('now'))," +
                            "last_checked TEXT NOT NULL," +
                            "is_banned INTEGER DEFAULT 0" +
                            ");");
                }
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        try {
            new Watcher(Path.of("/Users", "mayankmadan", "Tech", "Projects", "ssh-watcher", "ssh-watcher", "auth.log"))
                    .startWatching();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("SSH Watcher Ending");
    }
}
