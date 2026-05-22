package com.example.ct491.controllers;

import com.example.ct491.ssh.Connect;
import com.example.ct491.ssh.SseNotifier;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.concurrent.*;

@RestController
public class SSHController {

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private ObjectProvider<Connect> sshProvider;

    private final ExecutorService executor = Executors.newCachedThreadPool(); // Đa luồng

    @PostMapping("/connect-ssh")
    public List<Map<String, String>> checkAll(@RequestBody List<ServerRequest> servers) throws InterruptedException {
        List<Future<Map<String, String>>> futures = new ArrayList<>();

        for (ServerRequest s : servers) {
            Future<Map<String, String>> future = executor.submit(() -> {
                boolean isOnline = false;
                String osType = "Unknown";
                Connect ssh = sshProvider.getObject();
                try {
                    ssh.connect(s.host);
                    SseNotifier.notify("Connected successfully to host: " + s.host);
                    osType = detectOsType(ssh);
                    isOnline = true;
                } catch (Exception e) {
                    SseNotifier.notify("Connect failed for host " + s.host);
                } finally {
                    try {
                        jdbc.update("UPDATE servers SET os_type = ? WHERE host = ?", osType, s.host);
                    } catch (Exception e) {
                        System.err.println("DB update failed for host " + s.host + ": " + e.getMessage());
                    }
                    ssh.disconnect();
                }

                Map<String, String> m = new HashMap<>();
                m.put("host", s.host);
                m.put("status", isOnline ? "online" : "offline");
                m.put("os_type", osType);
                return m;
            });

            futures.add(future);
        }

        List<Map<String, String>> result = new ArrayList<>();
        for (Future<Map<String, String>> f : futures) {
            try {
                result.add(f.get());
            } catch (ExecutionException e) {
                e.printStackTrace();
            }
        }

        return result;
    }

    // Trả lại trạng thái đã (không kiểm tra lại)
    @GetMapping("/connect-ssh")
    public List<Map<String, String>> loadPreviousStatuses() {
        return jdbc.query("SELECT host, os_type FROM servers", (rs, rowNum) -> {
            Map<String, String> m = new HashMap<>();
            String osType = rs.getString("os_type");
            m.put("host", rs.getString("host"));
            m.put("os_type", osType != null ? osType : "Unknown");
            m.put("status", osType != null && !"Unknown".equals(osType) ? "online" : "offline");
            return m;
        });
    }

    private String detectOsType(Connect ssh) {
        try {
            String os = ssh.CommandExec("uname -s").trim();
            if (!os.isEmpty()) {
                return os;
            }
        } catch (Exception ignored) {
        }

        try {
            String os = ssh.CommandExec("ver > nul 2> nul && echo Windows").trim();
            if (!os.isEmpty()) {
                return os;
            }
        } catch (Exception ignored) {
        }

        return "Unknown";
    }

    public static class ServerRequest {

        public String host;
    }
}
