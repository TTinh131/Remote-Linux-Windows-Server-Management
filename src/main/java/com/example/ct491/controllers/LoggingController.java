package com.example.ct491.controllers;

import java.util.concurrent.ExecutorService;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.http.MediaType;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.*;
import java.text.SimpleDateFormat;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import com.example.ct491.ssh.Connect;
import com.fasterxml.jackson.databind.ObjectMapper;

@Controller
@RequestMapping("/logging")
public class LoggingController {

    @Autowired
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private ObjectProvider<Connect> connect;

    private static final String TEMP_DIR = Paths.get("src", "main", "resources", "temp").toString() + File.separator;
    private final ExecutorService executorService = Executors.newFixedThreadPool(8);
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    @ModelAttribute("user")
    public Map<String, Object> addUserToModel(HttpSession session) {
        Object userObj = session.getAttribute("user");
        if (userObj instanceof Map) {
            return (Map<String, Object>) userObj;
        }
        return null;
    }

    @GetMapping
    public String getLoggingPage(@RequestParam("host") String host, Model model, HttpSession session) {
        if (session.getAttribute("user") == null) {
            return "redirect:/";
        }
        Map<String, Object> server = jdbcTemplate.queryForMap("SELECT * FROM servers WHERE host = ?", host);
        model.addAttribute("server", server);
        return "logging";
    }

    private Future<String> execAsync(Connect conn, String command) {
        return executorService.submit(() -> {
            try {
                return conn.CommandExec(command);
            } catch (Exception e) {
                return "Error executing command: " + e.getMessage();
            }
        });
    }

    @GetMapping(value = "/api/logs", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getLogs(
            @RequestParam("host") String host,
            @RequestParam(value = "limit", defaultValue = "50") int limit,
            @RequestParam(value = "logType", required = false) String logType,
            @RequestParam(value = "fromDate", required = false) String fromDate,
            @RequestParam(value = "toDate", required = false) String toDate,
            HttpSession session) {
        if (session.getAttribute("user") == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
        }
        try {
            Map<String, Object> server = jdbcTemplate.queryForMap("SELECT * FROM servers WHERE host = ?", host);
            String osType = (String) server.get("os_type");
            String sudoPassword = (String) server.get("password");
            Map<String, Connect> Connects = (Map<String, Connect>) session.getAttribute("connectMap");
            if (Connects == null) {
                Connects = new HashMap<>();
                session.setAttribute("connectMap", Connects);
            }
            Connect conn = Connects.get(host);
            if (conn == null || !conn.isConnected()) {
                conn = connect.getObject();
                conn.connect(host);
                Connects.put(host, conn);
            }

            Map<String, Object> result = new HashMap<>();
            Map<String, Future<String>> futures = new HashMap<>();

            int perLogLimit = (int) Math.ceil(limit / 2);
            if ("linux".equalsIgnoreCase(osType)) {
                futures.put("system_logs", execAsync(conn, "echo '" + sudoPassword + "' | sudo -S tail -n " + perLogLimit + " /var/log/syslog"));
                futures.put("auth_logs", execAsync(conn, "echo '" + sudoPassword + "' | sudo -S tail -n " + perLogLimit + " /var/log/auth.log"));
            } else {
                futures.put("system_logs", execAsync(conn, "powershell -command \"Get-EventLog -LogName System -Newest " + perLogLimit + " | Format-List | Out-String\""));
                futures.put("security_logs", execAsync(conn, "powershell -command \"Get-EventLog -LogName Security -Newest " + perLogLimit + " | Format-List | Out-String\""));
            }
            for (Map.Entry<String, Future<String>> entry : futures.entrySet()) {
                result.put(entry.getKey(), entry.getValue().get());
            }

            List<Map<String, Object>> parsedLogs = parseLogs(result, osType, host, limit);
            parsedLogs = filterLogs(parsedLogs, logType, fromDate, toDate, limit);

            Map<String, Object> response = new HashMap<>();
            response.put("parsed_logs", parsedLogs);                    //tổng logs
            response.put("stats", calculateStats(parsedLogs));          //thống kê
            response.put("anomalies", detectAnomalies(parsedLogs));     //các bất thường (lỗi)
            response.put("timestamp", dateFormat.format(new Date()));   //time
            saveToJsonFile(host, response, "logs_");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Could not get logs: " + e.getMessage()));
        }
    }

    //chuyển dạng time của linux cho đồng dạng với win để đồng bộ
    private String convertLinuxTimestamp(String linuxTimestamp) {
        try {
            SimpleDateFormat inputFormat;
            if (linuxTimestamp.contains("-")) {
                inputFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");    //2023-06-15T14:30:00
            } else {
                inputFormat = new SimpleDateFormat("MMM dd HH:mm:ss");          //Jun 15 14:30:00)
                inputFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
                linuxTimestamp = linuxTimestamp + " " + new SimpleDateFormat("yyyy").format(new Date());
            }
            Date date = inputFormat.parse(linuxTimestamp);
            SimpleDateFormat outputFormat = new SimpleDateFormat("M/d/yyyy h:mm:ss a");
            return outputFormat.format(date);
        } catch (Exception e) {
            System.err.println("Error parsing timestamp: " + linuxTimestamp + ", error: " + e.getMessage());
            return linuxTimestamp;
        }
    }
    //lọc theo time

    private List<Map<String, Object>> filterLogs(List<Map<String, Object>> logs, String logType,
            String fromDate, String toDate, int limit) {
        List<Map<String, Object>> filtered = new ArrayList<>();
        SimpleDateFormat filterDateFormat = new SimpleDateFormat("M/d/yyyy h:mm:ss a");
        for (Map<String, Object> log : logs) {
            if (logType != null && !logType.isEmpty() && !logType.equals(log.get("source"))) {
                continue;
            }
            try {
                if (fromDate != null && !fromDate.isEmpty() && log.get("timestamp") != null) {
                    Date logDate = filterDateFormat.parse(log.get("timestamp").toString());
                    Date from = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm").parse(fromDate);
                    if (logDate.before(from)) {
                        continue;
                    }
                }
                if (toDate != null && !toDate.isEmpty() && log.get("timestamp") != null) {
                    Date logDate = filterDateFormat.parse(log.get("timestamp").toString());
                    Date to = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm").parse(toDate);
                    if (logDate.after(to)) {
                        continue;
                    }
                }
            } catch (Exception e) {
                System.err.println("Error parsing date: " + e.getMessage());
            }
            filtered.add(log);
            if (filtered.size() >= limit) {
                break;
            }
        }
        return filtered;
    }
    //xử lí đầu ra

    private List<Map<String, Object>> parseLogs(Map<String, Object> rawLogs, String osType, String host, int limit) {
        List<Map<String, Object>> logs = new ArrayList<>();

        if ("linux".equalsIgnoreCase(osType)) {
            parseLinuxLogs(rawLogs, host, logs);
        } else {
            parseWindowsLogs(rawLogs, host, logs);
        }
        return logs.size() > limit ? logs.subList(0, limit) : logs;
    }

    private void parseLinuxLogs(Map<String, Object> rawLogs, String host, List<Map<String, Object>> logs) {
        String syslog = (String) rawLogs.get("system_logs");
        if (syslog != null) {
            String[] lines = syslog.split("\n");
            for (String line : lines) {
                if (!line.trim().isEmpty()) {
                    Map<String, Object> logEntry = new HashMap<>();
                    String timestamp = line.substring(0, Math.min(20, line.length())).trim();
                    logEntry.put("timestamp", convertLinuxTimestamp(timestamp));

                    //"full_message"
                    logEntry.put("full_message", line.trim());
                    // Cắt phần message
                    String shortMessage;
                    if (line.matches(".*\\]:\\s.*")) {
                        shortMessage = line.replaceFirst(".*?\\]:\\s*", "");
                    } else if (line.matches(".*:\\s.*")) {
                        shortMessage = line.replaceFirst(".*?:\\s*", "");
                    } else {
                        shortMessage = line;
                    }
                    logEntry.put("message", shortMessage.trim());
                    logEntry.put("level", getLogLevel(line));
                    logEntry.put("source", "System");
                    logEntry.put("host", host);
                    logs.add(logEntry);
                }
            }
        }

        String authlog = (String) rawLogs.get("auth_logs");
        if (authlog != null) {
            String[] lines = authlog.split("\n");
            for (String line : lines) {
                if (!line.trim().isEmpty()) {
                    Map<String, Object> logEntry = new HashMap<>();
                    String timestamp = line.substring(0, Math.min(20, line.length())).trim();
                    logEntry.put("timestamp", convertLinuxTimestamp(timestamp));
                    // Lưu toàn bộ message gốc
                    logEntry.put("full_message", line.trim());
                    // Cắt phần message ngắn
                    String shortMessage;
                    if (line.contains("sudo:")) {
                        shortMessage = line.substring(line.indexOf("sudo:") + 5).trim();
                    } else if (line.matches(".*\\]:\\s.*")) {
                        shortMessage = line.replaceFirst(".*?\\]:\\s*", "");
                    } else if (line.matches(".*:\\s.*")) {
                        shortMessage = line.replaceFirst(".*?:\\s*", "");
                    } else {
                        shortMessage = line;
                    }
                    logEntry.put("message", shortMessage.trim());
                    logEntry.put("level", getLogLevel(line));
                    logEntry.put("source", "Authentication");
                    logEntry.put("host", host);
                    logs.add(logEntry);
                }
            }
        }
    }

    private void parseWindowsLogs(Map<String, Object> rawLogs, String host, List<Map<String, Object>> logs) {
        String syslog = (String) rawLogs.get("system_logs");
        if (syslog != null) {
            String[] entries = syslog.split("\\r?\\n\\r?\\n");
            for (String entry : entries) {
                if (!entry.trim().isEmpty()) {
                    Map<String, Object> logEntry = parseWindowsLogEntry(entry);
                    logEntry.put("source", "System");
                    logEntry.put("host", host);
                    logs.add(logEntry);
                }
            }
        }

        String seclog = (String) rawLogs.get("security_logs");
        if (seclog != null) {
            String[] entries = seclog.split("\\r?\\n\\r?\\n");
            for (String entry : entries) {
                if (!entry.trim().isEmpty()) {
                    Map<String, Object> logEntry = parseWindowsLogEntry(entry);
                    logEntry.put("source", "Security");
                    logEntry.put("host", host);
                    logs.add(logEntry);
                }
            }
        }
    }
    //phân loại

    private String getLogLevel(String logLine) {
        if (logLine.contains("error") || logLine.contains("ERROR")) {
            return "error";
        }
        if (logLine.contains("warn") || logLine.contains("WARN")) {
            return "warning";
        }
        if (logLine.contains("crit") || logLine.contains("CRIT")) {
            return "critical";
        }
        if (logLine.contains("fail") || logLine.contains("FAIL")) {
            return "error";
        }
        return "info";
    }
    //xử lí đầu ra log win

    private Map<String, Object> parseWindowsLogEntry(String entry) {
        Map<String, Object> logEntry = new HashMap<>();
        String[] lines = entry.split("\n");

        for (String line : lines) {
            if (line.startsWith("TimeGenerated")) {
                String timestamp = line.substring(line.indexOf(':') + 1).trim();
                logEntry.put("timestamp", convertLinuxTimestamp(timestamp));
            }
            if (line.startsWith("Message")) {
                logEntry.put("message", line.substring(line.indexOf(':') + 1).trim());
            }
            if (line.startsWith("EntryType")) {
                String level = line.substring(line.indexOf(':') + 1).trim().toLowerCase();
                switch (level) {
                    case "error":
                        logEntry.put("level", "error");
                        break;
                    case "warning":
                        logEntry.put("level", "warning");
                        break;
                    case "information":
                        logEntry.put("level", "info");
                        break;
                    case "successaudit":
                        logEntry.put("level", "success-audit");
                        break;
                    default:
                        logEntry.put("level", "info");
                }
            }
        }

        if (!logEntry.containsKey("timestamp")) {
            logEntry.put("timestamp", convertLinuxTimestamp(new Date().toString()));
        }
        if (!logEntry.containsKey("message")) {
            logEntry.put("message", entry);
        }
        if (!logEntry.containsKey("level")) {
            logEntry.put("level", "info");
        }

        return logEntry;
    }
    //Đếm số log theo: level, nguồn, tổng

    private Map<String, Object> calculateStats(List<Map<String, Object>> logs) {
        Map<String, Object> stats = new HashMap<>();
        Map<String, Integer> levelCount = new HashMap<>();
        Map<String, Integer> sourceCount = new HashMap<>();
        for (Map<String, Object> log : logs) {
            String level = log.get("level").toString();
            String source = log.get("source").toString();
            levelCount.put(level, levelCount.getOrDefault(level, 0) + 1);
            sourceCount.put(source, sourceCount.getOrDefault(source, 0) + 1);
        }
        stats.put("levelDistribution", levelCount);
        stats.put("sourceDistribution", sourceCount);
        stats.put("totalLogs", logs.size());
        return stats;
    }
    //kiểm tra log lỗi, quan trọng

    private List<Map<String, Object>> detectAnomalies(List<Map<String, Object>> logs) {
        List<Map<String, Object>> anomalies = new ArrayList<>();
        Map<String, Integer> errorRates = new HashMap<>();

        for (Map<String, Object> log : logs) {
            if ("error".equals(log.get("level")) || "critical".equals(log.get("level"))) {
                String source = log.get("source").toString();
                errorRates.put(source, errorRates.getOrDefault(source, 0) + 1);
                if (isCriticalLog(log)) {
                    anomalies.add(log);
                }
            }
        }

        for (Map.Entry<String, Integer> entry : errorRates.entrySet()) {
            if (entry.getValue() > 10) {
                anomalies.add(Map.of(
                        "type", "HighErrorRate",
                        "source", entry.getKey(),
                        "count", entry.getValue(),
                        "message", "High error rate detected in " + entry.getKey() + " logs"
                ));
            }
        }
        return anomalies;
    }

    private boolean isCriticalLog(Map<String, Object> log) {
        String message = log.get("message").toString().toLowerCase();
        return message.contains("fail") || message.contains("crash")
                || message.contains("out of memory") || message.contains("exception");
    }
    //xóa logs

    @PostMapping(value = "/api/clear-logs", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> clearLogs(
            @RequestParam("host") String host,
            HttpSession session) {

        if (session.getAttribute("user") == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
        }

        try {
            Map<String, Object> server = jdbcTemplate.queryForMap("SELECT * FROM servers WHERE host = ?", host);
            String osType = (String) server.get("os_type");
            String sudoPassword = (String) server.get("password");
            Map<String, Connect> Connects = (Map<String, Connect>) session.getAttribute("connectMap");
            Connect conn = Connects != null ? Connects.get(host) : null;

            if (conn == null || !conn.isConnected()) {
                return ResponseEntity.status(400).body(Map.of("error", "Not connected to server"));
            }

            String command;
            if ("linux".equalsIgnoreCase(osType)) {
                command = "echo '" + sudoPassword + "' | sudo -S truncate -s 0 /var/log/syslog && "
                        + "echo '" + sudoPassword + "' | sudo -S truncate -s 0 /var/log/auth.log && ";
            } else {
                command = "powershell -command \"Clear-EventLog -LogName System, Security; "
                        + "Clear-Content 'C:\\Program Files\\Suricata\\logs\\fast.log'\"";
            }
            String output = conn.CommandExec(command);
            return ResponseEntity.ok(Map.of("message", "Logs cleared successfully", "output", output));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Could not clear logs: " + e.getMessage()));
        }
    }
    //lưu file tạm

    private void saveToJsonFile(String host, Map<String, Object> data, String prefix) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            String jsonResult = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(data);
            String fileName = prefix + host + ".json";
            Files.createDirectories(Paths.get(TEMP_DIR));
            Path filePath = Paths.get(TEMP_DIR, fileName);
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath.toFile()))) {
                writer.write(jsonResult);
            }
        } catch (Exception e) {
            System.err.println("Could not save result file: " + e.getMessage());
        }
    }
}
