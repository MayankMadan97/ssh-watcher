package com.security.watcher.ssh;

import java.io.IOException;
import java.nio.file.Path;

public class App {
    public static void main(String[] args) {
        System.out.println("SSH Watcher starting");
        try {
            new Watcher(Path.of("/Users/mayankmadan/Tech/Projects/ssh-watcher/ssh-watcher/auth.log")).startWatching();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        System.out.println("SSH Watcher Ending");
    }
}
