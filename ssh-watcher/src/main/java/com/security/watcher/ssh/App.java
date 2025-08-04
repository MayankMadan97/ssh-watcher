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
                }
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }

        try {
            new Watcher(Path.of("/Users/mayankmadan/Tech/Projects/ssh-watcher/ssh-watcher/auth.log")).startWatching();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("SSH Watcher Ending");
    }
}
