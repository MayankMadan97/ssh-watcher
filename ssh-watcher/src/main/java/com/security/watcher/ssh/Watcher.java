package com.security.watcher.ssh;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Watcher {

    Path filePath;
    ProcessBuilder process;
    Logger logger;

    public Watcher(Path filePath) {
        this.filePath = filePath;
        this.logger = LoggerFactory.getLogger(Watcher.class);
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

    public void insertIntoDB(Map<String, Object> data) {
        this.logger.trace("Entering the method with data " + data.toString());
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

            pstmt.executeUpdate();

        } catch (SQLException e) {
            this.logger.warn("Failed to establish connection :: " + Arrays.toString(e.getStackTrace()));
        }
        this.logger.trace("Leaving the method");
    }

    public void checkForAnomoly(Set<String> sourceIP) {
        this.logger.trace("Entering the method with failed IPs: " + Arrays.toString(sourceIP.toArray()));
        if (sourceIP != null && sourceIP.size() > 0) {
            try (Connection conn = SQLiteConnectionManager.getConnection()) {
                try (Statement stmt = conn.createStatement()) {
                    sourceIP.stream()
                            .filter(Objects::nonNull)
                            .forEach(ip -> {
                                try {
                                    ResultSet failedAttempts = stmt
                                            .executeQuery("SELECT sourceIP, COUNT(*) AS failed_count FROM logins" +
                                                    " WHERE result = 'Failed' AND sourceIP = '" + ip
                                                    + "' AND timestamp > datetime('now', '-5 minutes') " +
                                                    "GROUP BY sourceIP HAVING failed_count >= 5");
                                    if (failedAttempts != null && failedAttempts.getString("sourceIP") != null) {
                                        this.logger.debug(failedAttempts.getString("sourceIP") + " >> "
                                                + failedAttempts.getString("failed_count"));
                                    }
                                } catch (SQLException e) {
                                    this.logger.warn("Failed to execute anomoly detection query :: "
                                            + Arrays.toString(e.getStackTrace()));
                                }
                            });
                }
            } catch (SQLException e) {
                this.logger.warn("Failed to establish connection :: " + Arrays.toString(e.getStackTrace()));
            }
        }
        this.logger.trace("Leaving the method");
    }

}
