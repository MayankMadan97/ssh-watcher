package com.security.watcher.ssh;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Pattern;

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
                        .forEach(line -> System.out.println(Extractor.extract(line).toString()));
            } else {
                throw new IOException("File at path \"" + filePath.toString() + "\" doesn't exist");
            }
        }
    }

}
