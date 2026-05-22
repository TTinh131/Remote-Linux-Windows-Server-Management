package com.example.ct491.ssh;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.*;

@Component
public class SshScheduler {

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private ObjectProvider<Connect> connect;

    // Map host → Connect instance
    private final Map<String, Connect> sessions = new ConcurrentHashMap<>();
    // Thread pool để xử lý song song
    private final ExecutorService executor = Executors.newFixedThreadPool(10); // 10 luồng
    @Scheduled(initialDelay = 0, fixedRate = 30_000)
    public void refreshAllServers() {
        System.out.println("Running Scheduler at " + new Date());
        List<Map<String, Object>> servers = jdbc.queryForList("SELECT host FROM servers");
        List<Future<?>> futures = new ArrayList<>();
        for (Map<String, Object> row : servers) {
            String host = (String) row.get("host");

            futures.add(executor.submit(() -> {
                sessions.putIfAbsent(host, connect.getObject());
                Connect conn = sessions.get(host);
                String osType = "Unknown";
                try {
                    conn.connect(host);
                    osType = detectOsType(conn);
                } catch (Exception ignored) {
                    // Kết nối thất bại → giữ osType = Unknown
                }
                jdbc.update(
                    "UPDATE servers SET os_type = ? WHERE host = ?",
                    osType, host
                );
            }));
        }
        // Chờ các task hoàn tất (có thể bỏ nếu không cần đồng bộ)
        for (Future<?> f : futures) {
            try {
                f.get();
            } catch (Exception e) {
                e.printStackTrace(); // Ghi log lỗi 
            }
        }
    }

    private String detectOsType(Connect conn) {
        try {
            String os = conn.CommandExec("uname -s").trim();
            if (!os.isEmpty()) return os;
        } catch (Exception ignored) {}

        try {
            String os = conn.CommandExec("ver > nul 2> nul && echo Windows").trim();
            if (!os.isEmpty()) return os;
        } catch (Exception ignored) {}

        return "Unknown";
    }
}
