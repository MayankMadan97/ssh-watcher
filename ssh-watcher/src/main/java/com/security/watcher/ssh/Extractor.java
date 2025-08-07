package com.security.watcher.ssh;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

public class Extractor {

    public static Map<String, Object> extract(String logLine) {
        Map<String, Object> extractedInfo = new HashMap<>();
        String[] parts = logLine.split("\s+");
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
            System.out.println("Log line format not recognized.");
        }
        return extractedInfo;
    }

    public static Map<String, Object> geoLocate(String sourceIP) {
        Map<String, Object> geoLocationData = new HashMap<>();
        if (sourceIP != null && sourceIP.contains(".")) {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request;
            try {
                request = HttpRequest.newBuilder()
                        .uri(new URI("http://ip-api.com/json/" + sourceIP + "?fields=58458111"))
                        .GET()
                        .build();
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                if (response != null && response.statusCode() == 200 && response.body() != null) {
                    geoLocationData = new ObjectMapper().readValue(response.body(),
                            new TypeReference<Map<String, Object>>() {
                            });
                }
            } catch (URISyntaxException | IOException | InterruptedException e) {
                System.out.println("Unable to geolocate IP: " + sourceIP);
            }

        }
        return geoLocationData;
    }
}
