package com.security.watcher.ssh;

import java.util.HashMap;
import java.util.Map;

public class Extractor {

    public static Map<String, Object> extract(String logLine) {
        Map<String, Object> extractedInfo = new HashMap<>();
        String[] parts = logLine.split("\\s+");
        if ((logLine.contains("publickey") || logLine.contains("password"))) {
            extractedInfo.put("timestamp", parts[0] + " " + parts[1] + " " + parts[2]);
            extractedInfo.put("result", parts[5]);
            extractedInfo.put("method", parts[6]);
            extractedInfo.put("user", parts[8]); // root
            extractedInfo.put("sourceIP", parts[10]); // 192.168.65.1
            extractedInfo.put("port", Integer.parseInt(parts[12])); // 20428

            // Add fingerprint if it exists (for publickey logins)
            if ("publickey".equals(parts[6]) && parts.length >= 16 && parts[15].startsWith("SHA256:")) {
                extractedInfo.put("fingerprint", parts[15].substring(7));
            }
        } else {
            System.out.println("⚠️ Log line format not recognized.");
        }
        return extractedInfo;
    }
}
