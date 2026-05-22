package com.example.ct491.controllers;

import com.example.ct491.ssh.Connect;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import jakarta.annotation.PreDestroy;
import jakarta.servlet.http.HttpSession;
import java.util.*;
import java.util.concurrent.*;

@Controller
@RequestMapping("/multiterminal")
public class MultiTerminalController {

    private final ExecutorService executorService = Executors.newFixedThreadPool(10);
    private final ConcurrentMap<String, Connect> activeConnections = new ConcurrentHashMap<>();

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private ObjectProvider<Connect> connectProvider;

    @ModelAttribute("user")
    public Map<String, Object> addUserToModel(HttpSession session) {
        Object userObj = session.getAttribute("user");
        return userObj instanceof Map ? (Map<String, Object>) userObj : null;
    }

    @GetMapping
    public String showMultiTerminal(Model model, HttpSession session) {
        if (session.getAttribute("user") == null) {
            return "redirect:/";
        }
        try {
            List<Map<String, Object>> servers = jdbcTemplate.queryForList(
                    "SELECT host, os_type, user FROM servers WHERE os_type != 'Unknown' ORDER BY host");
            if (servers.isEmpty()) {
                model.addAttribute("warning", "Hiện không có máy chủ nào đang online");
            }
            model.addAttribute("servers", servers);
            return "multi-terminal";
        } catch (Exception e) {
            model.addAttribute("error", "Lỗi hệ thống khi tải danh sách máy chủ: " + e.getMessage());
            return "multi-terminal";
        }
    }

    @ResponseBody
    @PostMapping("/execute")
    public Map<String, String> executeCommand(
            @RequestParam String host,
            @RequestParam String command,
            HttpSession session) {
        Map<String, String> response = new HashMap<>();

        if (session.getAttribute("user") == null) {
            response.put(host, "Phiên làm việc đã hết hạn");
            return response;
        }
        if (host == null || host.trim().isEmpty() || command == null || command.trim().isEmpty()) {
            response.put(host, "Thiếu thông tin máy chủ hoặc lệnh cần thực thi");
            return response;
        }
        try {
            Connect conn = activeConnections.computeIfAbsent(host, h -> {
                try {
                    Map<String, Object> server = jdbcTemplate.queryForMap(
                            "SELECT os_type, user FROM servers WHERE host = ? AND os_type != 'Unknown'", h);
                    String osType = (String) server.get("os_type");
                    if (osType == null || "Unknown".equalsIgnoreCase(osType)) {
                        return null;
                    }
                    Connect newConn = connectProvider.getObject();
                    newConn.setOsType(osType);
                    boolean connected = false;
                    for (int i = 0; i < 3; i++) {
                        try {
                            newConn.connect(h);
                            if ("linux".equalsIgnoreCase(osType)) {
                                newConn.connectShell();
                            }
                            connected = newConn.isConnected();
                            if (connected) {
                                break;
                            }
                            Thread.sleep(100);
                        } catch (Exception e) {
                            Thread.sleep(100);
                        }
                    }
                    if (!connected) {
                        return null;
                    }
                    return newConn;
                } catch (Exception e) {
                    return null;
                }
            });
            if (conn != null && conn.isConnected()) {
                String output;
                String osType = conn.getOsType();

                if ("windows".equalsIgnoreCase(osType)) {
                    output = conn.CommandExec(command);
                } else if ("linux".equalsIgnoreCase(osType)) {
                    output = cleanLinuxOutput(conn.CommandShellLinux(List.of(command)));
                } else {
                    output = "Hệ điều hành không được hỗ trợ";
                }
                response.put(host, output.isEmpty() ? "(Không có kết quả)" : output);
            } else {
                response.put(host, "Kết nối không khả dụng");
            }
        } catch (Exception e) {
            response.put(host, "Lỗi thực thi: " + e.getMessage());
        }
        return response;
    }

    @ResponseBody
    @PostMapping("/execute-multiple")
    public Map<String, String> executeOnMultipleServers(
            @RequestParam List<String> hosts,
            @RequestParam String command,
            HttpSession session) {

        if (session.getAttribute("user") == null) {
            return Collections.singletonMap("error", "Phiên làm việc đã hết hạn");
        }

        if (hosts == null || hosts.isEmpty() || command == null || command.trim().isEmpty()) {
            return Collections.singletonMap("error", "Thiếu thông tin máy chủ hoặc lệnh cần thực thi");
        }
        Map<String, String> results = new ConcurrentHashMap<>();
        List<CompletableFuture<Void>> futures = new ArrayList<>();
        for (String host : hosts) {
            futures.add(CompletableFuture.runAsync(() -> {
                try {
                    Connect conn = activeConnections.computeIfAbsent(host, h -> {
                        try {
                            Map<String, Object> server = jdbcTemplate.queryForMap(
                                    "SELECT os_type, user FROM servers WHERE host = ? AND os_type != 'Unknown'", h);
                            String osType = (String) server.get("os_type");
                            if (osType == null || "Unknown".equalsIgnoreCase(osType)) {
                                results.put(h, "Hệ điều hành không được hỗ trợ");
                                return null;
                            }
                            Connect newConn = connectProvider.getObject();
                            newConn.setOsType(osType);
                            boolean connected = false;
                            for (int i = 0; i < 3; i++) {
                                try {
                                    newConn.connect(h);
                                    if ("linux".equalsIgnoreCase(osType)) {
                                        newConn.connectShell();
                                    }
                                    connected = newConn.isConnected();
                                    if (connected) {
                                        break;
                                    }
                                    Thread.sleep(100);
                                } catch (Exception e) {
                                    Thread.sleep(100);
                                }
                            }
                            if (!connected) {
                                results.put(h, "Không thể kết nối sau 3 lần thử");
                                return null;
                            }
                            return newConn;
                        } catch (Exception e) {
                            results.put(h, "Không thể thiết lập kết nối: " + e.getMessage());
                            return null;
                        }
                    });
                    if (conn != null && conn.isConnected()) {
                        String output;
                        String osType = conn.getOsType();
                        if ("windows".equalsIgnoreCase(osType)) {
                            output = conn.CommandExec(command);
                        } else if ("linux".equalsIgnoreCase(osType)) {
                            output = cleanLinuxOutput(conn.CommandShellLinux(List.of(command)));
                        } else {
                            output = "Hệ điều hành không được hỗ trợ";
                        }
                        results.put(host, output.isEmpty() ? "(Không có kết quả)" : output);
                    } else {
                        results.put(host, "Kết nối không khả dụng");
                    }
                } catch (Exception e) {
                    results.put(host, "Lỗi thực thi: " + e.getMessage());
                }
            }, executorService));
        }
        try {
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                    .get(60, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            hosts.forEach(h -> results.putIfAbsent(h, "Timeout sau 60 giây"));
        } catch (Exception e) {
            hosts.forEach(h -> results.putIfAbsent(h, "Lỗi hệ thống: " + e.getMessage()));
        }
        Map<String, String> orderedResults = new LinkedHashMap<>();
        hosts.forEach(h -> orderedResults.put(h, results.getOrDefault(h, "Không có kết quả")));
        return orderedResults;
    }

    @PreDestroy
    public void cleanup() {
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
        activeConnections.forEach((host, conn) -> {
            try {
                if (conn != null && conn.isConnected()) {
                    conn.disconnect();
                }
            } catch (Exception e) {
            }
        });
        activeConnections.clear();
    }

    private String cleanLinuxOutput(String output) {
        if (output == null) {
            return "";
        }
        int idx = output.indexOf("[?2004l");
        if (idx != -1) {
            output = output.substring(idx + "[?2004l".length());
        }
        output = output.replaceAll("\u001B\\[[;\\d]*[ -/]*[@-~]", "");
        String[] lines = output.split("\r?\n");
        if (lines.length > 1) {
            lines = java.util.Arrays.copyOf(lines, lines.length - 1);
        }
        return String.join("\n", lines).trim();
    }
}
