package com.example.ct491.controllers;

import java.util.concurrent.ExecutorService;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import com.example.ct491.ssh.Connect;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.type.TypeReference;
import java.util.*;

@Controller
@RequestMapping("/firewall")
public class FirewallController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private ObjectProvider<Connect> connect;

    private static final String TEMP_DIR = Paths.get("src", "main", "resources", "temp").toString() + File.separator;
    private final ExecutorService executorService = Executors.newFixedThreadPool(8);

    @ModelAttribute("user")
    public Map<String, Object> addUserToModel(HttpSession session) {
        Object userObj = session.getAttribute("user");
        if (userObj instanceof Map) {
            return (Map<String, Object>) userObj;
        }
        return null;
    }

    @GetMapping
    public String getSecurityPage(@RequestParam("host") String host, Model model, HttpSession session) {
        if (session.getAttribute("user") == null) {
            return "redirect:/";
        }
        Map<String, Object> server = jdbcTemplate.queryForMap("SELECT * FROM servers WHERE host = ?", host);
        model.addAttribute("server", server);
        return "firewall";
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

    @GetMapping(value = "/api/firewall-status", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getFirewallStatus(
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

            if ("linux".equalsIgnoreCase(osType)) {
                futures.put("status", execAsync(conn,
                        "echo '" + sudoPassword + "' | sudo -S ufw status | grep 'Status'"));
                futures.put("total_rules", execAsync(conn,
                        "echo '" + sudoPassword + "' | sudo -S ufw status numbered | grep -c '\\]'"));
                futures.put("allow_rules", execAsync(conn,
                        "echo '" + sudoPassword + "' | sudo -S ufw status numbered | grep -c 'ALLOW'"));
                futures.put("deny_rules", execAsync(conn,
                        "echo '" + sudoPassword + "' | sudo -S ufw status numbered | grep -c 'DENY'"));
            } else {
                futures.put("status", execAsync(conn,
                        "netsh advfirewall show allprofiles state"));
                futures.put("total_rules", execAsync(conn,
                        "netsh advfirewall firewall show rule name=all | find \"Rule Name\" | find /c /v \"\""));
                futures.put("allow_rules", execAsync(conn,
                        "netsh advfirewall firewall show rule name=all | find \"Action:\" | find \"Allow\" | find /c /v \"\""));
                futures.put("deny_rules", execAsync(conn,
                        "netsh advfirewall firewall show rule name=all | find \"Action:\" | find \"Block\" | find /c /v \"\""));
                futures.put("enabled_rules", execAsync(conn,
                        "netsh advfirewall firewall show rule name=all | findstr /C:\"Enabled:                              Yes\" | find /c /v \"\""));
                futures.put("disabled_rules", execAsync(conn,
                        "netsh advfirewall firewall show rule name=all | findstr /C:\"Enabled:                              No\" | find /c /v \"\""));
            }

            for (Map.Entry<String, Future<String>> entry : futures.entrySet()) {
                String value = entry.getValue().get();
                if (entry.getKey().equals("status")) {
                    result.put(entry.getKey(),
                            "linux".equalsIgnoreCase(osType)
                            ? (value.toLowerCase().contains("status: active") ? "active" : "inactive")
                            : (value.toLowerCase().contains("on") ? "active" : "inactive"));
                } else {
                    result.put(entry.getKey(), value.trim());
                }
            }

            saveToJsonFile(host, result, "firewall_status_");
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Could not get firewall status: " + e.getMessage()));
        }
    }

    @PostMapping(value = "/api/firewall-toggle", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> toggleFirewall(
            @RequestParam("host") String host,
            @RequestParam("action") String action,
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
            String successMessage;

            if ("linux".equalsIgnoreCase(osType)) {
                if ("enable".equals(action)) {
                    command = "echo '" + sudoPassword + "' | sudo -S ufw --force enable";
                    successMessage = "Firewall enabled successfully";
                } else {
                    command = "echo '" + sudoPassword + "' | sudo -S ufw disable";
                    successMessage = "Firewall disabled successfully";
                }
            } else {
                if ("enable".equals(action)) {
                    command = "netsh advfirewall set allprofiles state on";
                    successMessage = "Firewall enabled successfully";
                } else {
                    command = "netsh advfirewall set allprofiles state off";
                    successMessage = "Firewall disabled successfully";
                }
            }

            String output = conn.CommandExec(command);
            return ResponseEntity.ok(Map.of(
                    "message", successMessage,
                    "output", output
            ));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Error toggling firewall: " + e.getMessage()));
        }
    }

    @GetMapping(value = "/api/firewall-rules", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getFirewallRules(
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

            List<Map<String, Object>> rules = new ArrayList<>();
            String command;

            if ("linux".equalsIgnoreCase(osType)) {
                command = "echo '" + sudoPassword + "' | sudo -S ufw status numbered";
                String output = conn.CommandExec(command);
                String[] lines = output.split("\n");

                for (String line : lines) {
                    if (line.contains("]") && (line.contains("ALLOW") || line.contains("DENY"))) {
                        Map<String, Object> rule = parseUfwRule(line);
                        rules.add(rule);
                    }
                }
            } else {
                command = "netsh advfirewall firewall show rule name=all";
                String output = conn.CommandExec(command);
                String[] ruleBlocks = output.split("----------------------------------------------------------------------\r?\n");

                for (int i = 1; i < ruleBlocks.length; i++) {
                    String block = ruleBlocks[i].trim();
                    if (!block.isEmpty()) {
                        try {
                            Map<String, Object> rule = parseWindowsFirewallRule(block);
                            if (!rule.isEmpty()) {
                                rules.add(rule);
                            }
                        } catch (Exception e) {
                            // Ghi log lỗi nhưng tiếp tục xử lý các rule khác
                            System.err.println("Error parsing rule block: " + e.getMessage());
                        }
                    }
                }
            }

            saveToJsonFile(host, Map.of("rules", rules), "firewall_rules_");
            return ResponseEntity.ok(Map.of("rules", rules));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Could not get firewall rules: " + e.getMessage()));
        }
    }

    private Map<String, Object> parseUfwRule(String line) {
        Map<String, Object> rule = new HashMap<>();
        // Trích xuất ID quy tắc
        int start = line.indexOf("[") + 1;
        int end = line.indexOf("]");
        rule.put("id", line.substring(start, end).trim());

        // action
        rule.put("action", line.contains("ALLOW") ? "allow" : "deny");

        String[] parts = line.substring(end + 1).trim().split(" ");
        rule.put("protocol", parts[0].toLowerCase());

        if (parts.length > 1) {
            String source = parts[1];
            if (source.contains(":")) {
                rule.put("source_ip", source.split(":")[0]);
                rule.put("source_port", source.split(":")[1]);
            } else {
                rule.put("source_ip", source);
                rule.put("source_port", "any");
            }
        }

        if (parts.length > 3) {
            String dest = parts[3];
            if (dest.contains(":")) {
                rule.put("destination_ip", dest.split(":")[0]);
                rule.put("destination_port", dest.split(":")[1]);
            } else {
                rule.put("destination_ip", dest);
                rule.put("destination_port", "any");
            }
        }

        rule.put("status", "active");
        return rule;
    }

    private Map<String, Object> parseWindowsFirewallRule(String block) {
        Map<String, Object> rule = new HashMap<>();
        String[] lines = block.split("\n");
        String fullRuleName = "";

        for (String line : lines) {
            if (line.contains(":")) {
                String[] keyValue = line.split(":", 2);
                String key = keyValue[0].trim().toLowerCase().replace(" ", "_");
                String value = keyValue[1].trim();

                switch (key) {
                    case "rule_name":
                        fullRuleName = value;
                        // Tạo tên hiển thị ngắn
                        String displayName = fullRuleName.length() > 8
                                ? fullRuleName.substring(0, 5) + "..."
                                : fullRuleName;
                        rule.put("id", displayName);
                        rule.put("full_name", fullRuleName); // Lưu tên đầy đủ
                        break;
                    case "enabled":
                        rule.put("status", "yes".equalsIgnoreCase(value) ? "active" : "inactive");
                        break;
                    case "direction":
                        rule.put("type", value.toLowerCase());
                        break;
                    case "action":
                        rule.put("action", value.toLowerCase());
                        break;
                    case "remoteip":
                        rule.put("source_ip", value);
                        break;
                    case "localip":
                        rule.put("destination_ip", value);
                        break;
                    case "protocol":
                        rule.put("protocol", value.toLowerCase());
                        break;
                    case "localport":
                        rule.put("destination_port", value);
                        break;
                    case "remoteport":
                        rule.put("source_port", value);
                        break;
                }
            }
        }
        return rule;
    }

    @PostMapping(value = "/api/firewall-rules", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> addFirewallRule(
            @RequestBody Map<String, Object> ruleData,
            HttpSession session) {

        if (session.getAttribute("user") == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
        }

        try {
            String host = (String) ruleData.get("host");
            Map<String, Object> server = jdbcTemplate.queryForMap("SELECT * FROM servers WHERE host = ?", host);
            String osType = (String) server.get("os_type");
            String sudoPassword = (String) server.get("password");
            Map<String, Connect> Connects = (Map<String, Connect>) session.getAttribute("connectMap");
            Connect conn = Connects != null ? Connects.get(host) : null;

            if (conn == null || !conn.isConnected()) {
                return ResponseEntity.status(400).body(Map.of("error", "Not connected to server"));
            }

            String command;
            String ruleId = UUID.randomUUID().toString();

            if ("linux".equalsIgnoreCase(osType)) {
                command = String.format(
                        "echo '%s' | sudo -S ufw insert 1 %s from %s to %s port %s proto %s",
                        sudoPassword,
                        ruleData.get("action"),
                        ruleData.get("source_ip"),
                        ruleData.get("destination_ip"),
                        ruleData.get("port_range"),
                        ruleData.get("protocol")
                );
            } else {
                String deleteCommand = String.format(
                        "netsh advfirewall firewall delete rule name=\"%s\"",
                        ruleId
                );
                conn.CommandExec(deleteCommand);

                String portRange = (String) ruleData.get("port_range");
                String portParam = "any".equals(portRange) || portRange.isEmpty()
                        ? ""
                        : " localport=" + portRange;

                command = String.format(
                        "netsh advfirewall firewall add rule name=\"%s\" dir=%s action=%s protocol=%s remoteip=%s localip=%s%s enable=yes",
                        ruleId,
                        ruleData.get("type"),
                        "allow".equals(ruleData.get("action")) ? "allow" : "block",
                        ruleData.get("protocol"),
                        ruleData.get("source_ip"),
                        ruleData.get("destination_ip"),
                        portParam
                );
            }

            String output = conn.CommandExec(command);
            return ResponseEntity.ok(Map.of(
                    "message", "Firewall rule added successfully",
                    "rule_id", ruleId,
                    "output", output
            ));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Error adding firewall rule: " + e.getMessage()));
        }
    }

    @DeleteMapping(value = "/api/firewall-rules/{ruleId}", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> deleteFirewallRule(
            @PathVariable String ruleId,
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
            String output;

            if ("linux".equalsIgnoreCase(osType)) {
                try {
                    Integer.parseInt(ruleId);
                } catch (NumberFormatException e) {
                    return ResponseEntity.status(400).body(Map.of("error", "For Linux, ruleId must be a number"));
                }

                command = String.format("echo '%s' | sudo -S ufw --force delete %s", sudoPassword, ruleId);
            } else {
                // Trên Windows, cần lấy full_name của rule trước khi xóa
                String getRuleCommand = "netsh advfirewall firewall show rule name=all";
                String rulesOutput = conn.CommandExec(getRuleCommand);
                String[] ruleBlocks = rulesOutput.split("----------------------------------------------------------------------\r?\n");

                String fullRuleName = null;
                for (int i = 1; i < ruleBlocks.length; i++) {
                    String block = ruleBlocks[i].trim();
                    if (!block.isEmpty()) {
                        Map<String, Object> rule = parseWindowsFirewallRule(block);
                        String displayName = (String) rule.get("id");
                        if (ruleId.equals(displayName)) {
                            fullRuleName = (String) rule.get("full_name");
                            break;
                        }
                    }
                }

                if (fullRuleName == null) {
                    return ResponseEntity.status(404).body(Map.of("error", "Rule not found"));
                }

                command = String.format("netsh advfirewall firewall delete rule name=\"%s\"", fullRuleName);
            }
            output = conn.CommandExec(command);
            if (output.toLowerCase().contains("error") || output.toLowerCase().contains("not found")) {
                return ResponseEntity.status(404).body(Map.of("error", output.trim()));
            }

            return ResponseEntity.ok(Map.of(
                    "message", "Firewall rule deleted successfully",
                    "output", output
            ));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Error deleting firewall rule: " + e.getMessage()));
        }
    }

    @PutMapping(value = "/api/firewall-rules/{ruleId}", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> updateFirewallRule(
            @PathVariable String ruleId,
            @RequestBody Map<String, Object> ruleData,
            HttpSession session) {

        if (session.getAttribute("user") == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
        }

        try {
            String host = (String) ruleData.get("host");
            Map<String, Object> server = jdbcTemplate.queryForMap("SELECT * FROM servers WHERE host = ?", host);
            String osType = (String) server.get("os_type");
            String sudoPassword = (String) server.get("password");
            Map<String, Connect> Connects = (Map<String, Connect>) session.getAttribute("connectMap");
            Connect conn = Connects != null ? Connects.get(host) : null;

            if (conn == null || !conn.isConnected()) {
                return ResponseEntity.status(400).body(Map.of("error", "Not connected to server"));
            }

            String command;
            String successMessage;

            if ("linux".equalsIgnoreCase(osType)) {
                // xóa rule cũ
                String deleteCommand = String.format(
                        "echo '%s' | sudo -S ufw --force delete %s",
                        sudoPassword,
                        ruleId
                );
                conn.CommandExec(deleteCommand);
                // Thêmm lại rule mới
                command = String.format(
                        "echo '%s' | sudo -S ufw %s from %s to %s port %s proto %s",
                        sudoPassword,
                        ruleData.get("action"),
                        ruleData.get("source_ip"),
                        ruleData.get("destination_ip"),
                        ruleData.get("port_range"),
                        ruleData.get("protocol")
                );
                successMessage = "Firewall rule updated successfully";
            } else {
                // lấy full name
                String getRuleCommand = "netsh advfirewall firewall show rule name=all";
                String rulesOutput = conn.CommandExec(getRuleCommand);
                String[] ruleBlocks = rulesOutput.split("----------------------------------------------------------------------\r?\n");

                String fullRuleName = null;
                for (int i = 1; i < ruleBlocks.length; i++) {
                    String block = ruleBlocks[i].trim();
                    if (!block.isEmpty()) {
                        Map<String, Object> rule = parseWindowsFirewallRule(block);
                        String displayName = (String) rule.get("id");
                        if (ruleId.equals(displayName)) {
                            fullRuleName = (String) rule.get("full_name");
                            break;
                        }
                    }
                }

                if (fullRuleName == null) {
                    return ResponseEntity.status(404).body(Map.of("error", "Rule not found"));
                }

                // xóa rules cũ
                String deleteCommand = String.format(
                        "netsh advfirewall firewall delete rule name=\"%s\"",
                        fullRuleName
                );
                conn.CommandExec(deleteCommand);

                // thêm rule mới
                String newRuleName = UUID.randomUUID().toString();

                String portRange = (String) ruleData.get("port_range");
                String portParam = "any".equals(portRange) || portRange.isEmpty()
                        ? ""
                        : " localport=" + portRange;

                command = String.format(
                        "netsh advfirewall firewall add rule name=\"%s\" dir=%s action=%s protocol=%s remoteip=%s localip=%s%s enable=yes",
                        newRuleName,
                        ruleData.get("type"),
                        "allow".equals(ruleData.get("action")) ? "allow" : "block",
                        ruleData.get("protocol"),
                        ruleData.get("source_ip"),
                        ruleData.get("destination_ip"),
                        portParam
                );
                successMessage = "Firewall rule updated successfully";
            }

            String output = conn.CommandExec(command);
            return ResponseEntity.ok(Map.of(
                    "message", successMessage,
                    "output", output
            ));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Error updating firewall rule: " + e.getMessage()));
        }
    }

    @GetMapping(value = "/api/firewall-logs", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getFirewallLogs(
            @RequestParam("host") String host,
            @RequestParam(value = "lines", defaultValue = "50") int lines,
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

            List<Map<String, Object>> logs = new ArrayList<>();
            String command;

            if ("linux".equalsIgnoreCase(osType)) {
                command = "echo '" + sudoPassword + "' | sudo -S tail -n " + lines + " /var/log/ufw.log";
                String output = conn.CommandExec(command);
                String[] logLines = output.split("\n");

                for (String line : logLines) {
                    if (line.contains("UFW")) {
                        Map<String, Object> logEntry = parseUfwLogEntry(line);
                        logs.add(logEntry);
                    }
                }
            } else {
                command = "powershell -command \"Get-Content 'C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log' -Tail " + lines
                        + " | Where-Object { $_ -match '^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2} (ALLOW|DROP) (TCP|UDP|ICMP|\\d+) \\S+ \\S+' }\"";
                String output = conn.CommandExec(command);
                if (output != null && !output.trim().isEmpty()) {
                    String[] logLines = output.split("\\r?\\n");

                    for (String line : logLines) {
                        line = line.trim();
                        if (line.isEmpty()) {
                            continue;
                        }
                        System.out.println("Processing line: " + line); // Debug log
                        Map<String, Object> logEntry = parseWindowsFirewallLogEntry(line);
                        // Debug từng trường sau khi parse
                        System.out.println("Parsed entry: " + logEntry);
                        logs.add(logEntry);
                    }
                }
            }

            saveToJsonFile(host, Map.of("logs", logs), "firewall_logs_");
            return ResponseEntity.ok(Map.of("logs", logs));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Could not get firewall logs: " + e.getMessage()));
        }
    }

    private Map<String, Object> parseUfwLogEntry(String line) {
        Map<String, Object> logEntry = new HashMap<>();

        logEntry.put("timestamp", line.substring(0, line.indexOf(" ")));

        if (line.contains("UFW ALLOW")) {
            logEntry.put("action", "allow");
        } else if (line.contains("UFW BLOCK")) {
            logEntry.put("action", "deny");
        }

        if (line.contains("PROTO=TCP")) {
            logEntry.put("protocol", "tcp");
        } else if (line.contains("PROTO=UDP")) {
            logEntry.put("protocol", "udp");
        } else if (line.contains("PROTO=ICMP")) {
            logEntry.put("protocol", "icmp");
        }

        if (line.contains("SRC=")) {
            String src = line.substring(line.indexOf("SRC=") + 4);
            src = src.substring(0, src.indexOf(" "));
            logEntry.put("source_ip", src);
        }

        if (line.contains("DST=")) {
            String dst = line.substring(line.indexOf("DST=") + 4);
            dst = dst.substring(0, dst.indexOf(" "));
            logEntry.put("destination_ip", dst);
        }

        if (line.contains("SPT=")) {
            String spt = line.substring(line.indexOf("SPT=") + 4);
            spt = spt.substring(0, spt.indexOf(" "));
            logEntry.put("source_port", spt);
        }

        if (line.contains("DPT=")) {
            String dpt = line.substring(line.indexOf("DPT=") + 4);
            dpt = dpt.substring(0, dpt.indexOf(" "));
            logEntry.put("destination_port", dpt);
        }

        logEntry.put("message", line);
        return logEntry;
    }

    private Map<String, Object> parseWindowsFirewallLogEntry(String line) {
        Map<String, Object> logEntry = new LinkedHashMap<>();

        try {
            // Tách các phần cơ bản trước bằng split()
            String[] parts = line.split("\\s+", 8); // Chỉ tách 8 phần đầu

            if (parts.length >= 8) {
                // Xử lý các trường cơ bản
                logEntry.put("timestamp", parts[0] + " " + parts[1]);
                logEntry.put("action", parts[2].toLowerCase());
                logEntry.put("protocol", parts[3].toLowerCase());
                logEntry.put("source_ip", parts[4]);
                logEntry.put("destination_ip", parts[5]);

                // Xử lý port (bỏ qua nếu là "-")
                if (!parts[6].equals("-")) {
                    logEntry.put("source_port", parts[6]);
                }
                if (!parts[7].equals("-")) {
                    logEntry.put("destination_port", parts[7]);
                }

                // Xác định hướng kết nối (từ cuối dòng)
                if (line.contains("SEND")) {
                    logEntry.put("direction", "out");
                } else if (line.contains("RECEIVE")) {
                    logEntry.put("direction", "in");
                }

                // Thêm raw message để debug
                logEntry.put("raw", line);
            } else {
                throw new IllegalArgumentException("Invalid log format - not enough fields");
            }
        } catch (Exception e) {
            logEntry.put("error", "Parse error: " + e.getMessage());
            logEntry.put("raw", line);
        }

        return logEntry;
    }

    @DeleteMapping(value = "/api/firewall-logs/clear", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> clearFirewallLogs(
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
                command = "echo '" + sudoPassword + "' | sudo -S truncate -s 0 /var/log/ufw.log";
            } else {
                command = "wevtutil cl Security";
            }

            String output = conn.CommandExec(command);
            return ResponseEntity.ok(Map.of(
                    "message", "Firewall logs cleared successfully",
                    "output", output
            ));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Error clearing firewall logs: " + e.getMessage()));
        }
    }

    @GetMapping(value = "/api/firewall-status/readFile", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getFirewallStatusFromFile(
            @RequestParam("host") String host,
            HttpSession session) {

        if (session.getAttribute("user") == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
        }

        Map<String, Object> status = readFile(host, "firewall_status_");
        if (status != null) {
            return ResponseEntity.ok(status);
        } else {
            return ResponseEntity.status(404)
                    .body(Map.of("error", "File not found or could not be read"));
        }
    }

    @GetMapping(value = "/api/firewall-rules/readFile", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getFirewallRulesFromFile(
            @RequestParam("host") String host,
            HttpSession session) {

        if (session.getAttribute("user") == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
        }

        Map<String, Object> rules = readFile(host, "firewall_rules_");
        if (rules != null) {
            return ResponseEntity.ok(rules);
        } else {
            return ResponseEntity.status(404)
                    .body(Map.of("error", "File not found or could not be read"));
        }
    }

    @GetMapping(value = "/api/firewall-logs/readFile", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getFirewallLogsFromFile(
            @RequestParam("host") String host,
            HttpSession session) {

        if (session.getAttribute("user") == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
        }

        Map<String, Object> logs = readFile(host, "firewall_logs_");
        if (logs != null) {
            return ResponseEntity.ok(logs);
        } else {
            return ResponseEntity.status(404)
                    .body(Map.of("error", "File not found or could not be read"));
        }
    }

    @GetMapping(value = "/api/firewall-rule-details", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getFirewallRuleDetails(
            @RequestParam("host") String host,
            @RequestParam("ruleId") String ruleId,
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

            Map<String, Object> ruleDetails = new HashMap<>();
            String command;

            if ("linux".equalsIgnoreCase(osType)) {
                command = "echo '" + sudoPassword + "' | sudo -S ufw status numbered";
                String output = conn.CommandExec(command);
                String[] lines = output.split("\n");

                for (String line : lines) {
                    if (line.contains("[" + ruleId + "]")) {
                        ruleDetails = parseUfwRule(line);
                        break;
                    }
                }
            } else {
                command = "netsh advfirewall firewall show rule name=\"" + ruleId + "\"";
                String output = conn.CommandExec(command);
                ruleDetails = parseWindowsFirewallRule(output);
            }

            if (ruleDetails.isEmpty()) {
                return ResponseEntity.status(404).body(Map.of("error", "Rule not found"));
            }

            return ResponseEntity.ok(ruleDetails);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Could not get rule details: " + e.getMessage()));
        }
    }

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

    private Map<String, Object> readFile(String host, String prefix) {
        try {
            String fileName = prefix + host + ".json";
            Path filePath = Paths.get(TEMP_DIR, fileName);

            if (!Files.exists(filePath)) {
                System.err.println("File does not exist: " + filePath);
                return null;
            }

            String content = new String(Files.readAllBytes(filePath));
            ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.readValue(content, new TypeReference<Map<String, Object>>() {
            });
        } catch (Exception e) {
            System.err.println("Error reading JSON file: " + e.getMessage());
            return null;
        }
    }

    @PatchMapping(value = "/api/firewall-rules/{ruleId}/toggle", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> toggleRuleStatus(
            @PathVariable String ruleId,
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
            String successMessage;

            if ("linux".equalsIgnoreCase(osType)) {
                command = String.format("echo '%s' | sudo -S ufw %s %s",
                        sudoPassword,
                        ruleId.contains("enable") ? "enable" : "disable",
                        ruleId);
                successMessage = String.format("Rule %s %s successfully",
                        ruleId, ruleId.contains("enable") ? "enabled" : "disabled");
            } else {
                String getRuleCommand = String.format("netsh advfirewall firewall show rule name=\"%s\"", ruleId);
                String output = conn.CommandExec(getRuleCommand);
                boolean isEnabled = output.toLowerCase().contains("enabled: yes");
                command = String.format("netsh advfirewall firewall set rule name=\"%s\" new enable=%s",
                        ruleId,
                        isEnabled ? "no" : "yes");
                successMessage = String.format("Rule %s %s successfully",
                        ruleId, isEnabled ? "disabled" : "enabled");
            }

            String output = conn.CommandExec(command);
            return ResponseEntity.ok(Map.of(
                    "message", successMessage,
                    "output", output
            ));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Error toggling rule status: " + e.getMessage()));
        }
    }

    @GetMapping(value = "/api/firewall-security-summary", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getFirewallSecuritySummary(
            @RequestParam("host") String host,
            HttpSession session) {

        if (session.getAttribute("user") == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
        }

        try {
            // Lấy 50 log gần nhất
            ResponseEntity<Map<String, Object>> logsResponse = getFirewallLogs(host, 50, session);
            if (logsResponse.getStatusCode() != HttpStatus.OK) {
                return logsResponse;
            }

            Map<String, Object> logsData = logsResponse.getBody();
            List<Map<String, Object>> logs = (List<Map<String, Object>>) logsData.get("logs");

            // Phân tích logs
            Map<String, Object> summary = new HashMap<>();
            summary.put("totalEvents", logs.size());

            long denyCount = logs.stream().filter(log -> "deny".equalsIgnoreCase((String) log.get("action"))).count();
            summary.put("denyEvents", denyCount);

            long allowCount = logs.stream().filter(log -> "allow".equalsIgnoreCase((String) log.get("action"))).count();
            summary.put("allowEvents", allowCount);

            long multicastCount = logs.stream()
                    .filter(log -> {
                        String destIp = (String) log.get("destination_ip");
                        return destIp != null && destIp.startsWith("224.");
                    })
                    .count();
            summary.put("multicastEvents", multicastCount);

            // Top IP
            Map<String, Long> ipCounts = logs.stream()
                    .collect(Collectors.groupingBy(
                            log -> (String) log.get("source_ip"),
                            Collectors.counting()
                    ));

            Optional<Map.Entry<String, Long>> topIp = ipCounts.entrySet().stream()
                    .max(Map.Entry.comparingByValue());

            if (topIp.isPresent()) {
                summary.put("topSourceIp", topIp.get().getKey());
                summary.put("topSourceIpCount", topIp.get().getValue());
            }

            return ResponseEntity.ok(summary);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Could not analyze firewall logs: " + e.getMessage()));
        }
    }

    @GetMapping(value = "/api/firewall-security-warnings", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getFirewallSecurityWarnings(
            @RequestParam("host") String host,
            HttpSession session) {

        if (session.getAttribute("user") == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
        }

        try {
            // Lấy 50 log gần nhất
            ResponseEntity<Map<String, Object>> logsResponse = getFirewallLogs(host, 50, session);
            if (logsResponse.getStatusCode() != HttpStatus.OK) {
                return logsResponse;
            }

            Map<String, Object> logsData = logsResponse.getBody();
            List<Map<String, Object>> logs = (List<Map<String, Object>>) logsData.get("logs");

            List<Map<String, Object>> warnings = new ArrayList<>();

            // Phân tích IP bị từ chối
            Map<String, Long> deniedIps = logs.stream()
                    .filter(log -> "deny".equalsIgnoreCase((String) log.get("action")))
                    .collect(Collectors.groupingBy(
                            log -> (String) log.get("source_ip"),
                            Collectors.counting()
                    ));

            deniedIps.entrySet().stream()
                    .filter(entry -> entry.getValue() > 4) // Ngưỡng cảnh báo: 5 lần
                    .forEach(entry -> {
                        Map<String, Object> warning = new HashMap<>();
                        warning.put("type", "FrequentDenials");
                        warning.put("title", "Frequent denied attempts");
                        warning.put("description", "IP " + entry.getKey() + " was denied " + entry.getValue() + " times");
                        warning.put("ip", entry.getKey());
                        warning.put("count", entry.getValue());
                        warnings.add(warning);
                    });
            // Sắp xếp theo số lần từ chối giảm dần
            warnings.sort((a, b) -> (int) ((Long) b.get("count") - (Long) a.get("count")));
            Map<String, Object> response = new HashMap<>();
            response.put("warnings", warnings);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Could not analyze firewall logs: " + e.getMessage()));
        }
    }
}
