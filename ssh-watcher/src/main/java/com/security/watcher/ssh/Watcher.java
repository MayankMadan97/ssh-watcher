package com.security.watcher.ssh;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Map;

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
                Files.lines(filePath)
                        .filter(line -> !line.trim().isEmpty()
                                && line.contains("Accepted") || line.contains("Failed"))
                        .forEach(line -> {
                            Map<String, Object> loginInfo = Extractor.extract(line);
                            if (loginInfo != null && loginInfo.containsKey("sourceIP")) {
                                loginInfo.put("geoLocation", Extractor.geoLocate(loginInfo.get("sourceIP").toString()));
                                insertIntoDB(loginInfo);
                                System.out.println(loginInfo.toString());
                            }
                        });
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
            pstmt.setString(5, data.get("port").toString());
            pstmt.setString(6, data.get("geoLocation").toString());
            pstmt.setString(7, data.get("method").toString());

            pstmt.executeUpdate();
            System.out.println("✅ Inserted into SQLite");

        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

}
