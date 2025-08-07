package com.security.watcher.ssh;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Watcher {

    Path filePath;
    ProcessBuilder process;

    public Watcher(Path filePath) {
        this.filePath = filePath;
    }

    public Watcher(String command) {
        if (command != null && command.trim().length() > 0) {
            this.process = new ProcessBuilder(command.trim().split(" "));
        } else {
            throw new IllegalArgumentException("Commands empty");
        }
    }

    public void startWatching() throws IOException {
        if (this.filePath != null) {
            // Firstly, check if the file exists
            if (Files.exists(filePath)) {
                Set<String> failedSourceIps = new HashSet<>();
                Files.lines(filePath)
                        .filter(line -> !line.trim().isEmpty()
                                && line.contains("Accepted") || line.contains("Failed"))
                        .forEach(line -> {
                            Map<String, Object> loginInfo = Extractor.extract(line);
                            if (loginInfo != null && loginInfo.containsKey("sourceIP")) {
                                loginInfo.put("geoLocation", Extractor.geoLocate(loginInfo.get("sourceIP").toString()));
                                insertIntoDB(loginInfo);
                                if (loginInfo.get("result").toString().equalsIgnoreCase("failed")) {
                                    failedSourceIps.add(loginInfo.get("sourceIP").toString());
                                }
                            }
                        });
                if (failedSourceIps.size() > 0) {
                    checkForAnomoly(failedSourceIps);
                }
            } else {
                throw new IOException("File at path \"" + filePath.toString() + "\" doesn't exist");
            }
        }
    }

    public static void insertIntoDB(Map<String, Object> data) {
        String sql = "INSERT INTO logins(sourceIP,timestamp,result,user,port, geoLocation, method) VALUES(?, ?, ?,?, ?, ?,?)";

        try (Connection conn = SQLiteConnectionManager.getConnection();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, data.get("sourceIP").toString());
            pstmt.setString(2, data.get("timestamp").toString());
            pstmt.setString(3, data.get("result").toString());
            pstmt.setString(4, data.get("user").toString());
            pstmt.setInt(5, Integer.parseInt(data.get("port").toString()));
            pstmt.setString(6, data.get("geoLocation").toString());
            pstmt.setString(7, data.get("method").toString());

            System.out.println(pstmt.executeUpdate());

        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void checkForAnomoly(Set<String> sourceIP) {
        if (sourceIP != null) {
            try (Connection conn = SQLiteConnectionManager.getConnection()) {
                if (conn != null) {
                    try (Statement stmt = conn.createStatement()) {
                        if (sourceIP != null && sourceIP.size() > 0) {
                            sourceIP.stream().forEach(ip -> {
                                ResultSet failedAttempts;
                                try {
                                    failedAttempts = stmt
                                            .executeQuery("SELECT sourceIP, COUNT(*) AS failed_count FROM logins" +
                                                    " WHERE result = 'Failed' AND sourceIP = '" + ip
                                                    + "' AND timestamp > datetime('now', '-5 minutes') " +
                                                    "GROUP BY sourceIP HAVING failed_count >= 5");
                                    if (failedAttempts != null) {
                                        System.out.println(failedAttempts.getString("sourceIP") + " >> "
                                                + failedAttempts.getString("failed_count"));
                                    }
                                } catch (SQLException e) {
                                    // TODO Auto-generated catch block
                                    e.printStackTrace();
                                }
                            });
                        }
                    }
                }
            } catch (SQLException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }

}
