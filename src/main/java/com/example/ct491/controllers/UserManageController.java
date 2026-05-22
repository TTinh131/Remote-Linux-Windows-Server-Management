package com.example.ct491.controllers;

import java.util.concurrent.ExecutorService;
import java.nio.file.Files;
import java.nio.file.Paths;

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
import org.springframework.http.MediaType;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import com.fasterxml.jackson.core.type.TypeReference;
import java.util.*;

@Controller
@RequestMapping("/user-management")
public class UserManageController {

    //Danh sách các lệnh nguy hiểm
    private static final Map<String, String> DANGEROUS_COMMANDS = Map.ofEntries(
            Map.entry("sudo", "Attempt to elevate privileges"),
            Map.entry("su", "User switching attempt"),
            Map.entry("passwd", "Password modification attempt"),
            Map.entry("chmod", "Permission modification"),
            Map.entry("chown", "Ownership change"),
            Map.entry("rm -rf", "Dangerous deletion command"),
            Map.entry("wget", "File download"),
            Map.entry("curl", "File download"),
            Map.entry("ssh", "Remote connection attempt"),
            Map.entry("scp", "File transfer"),
            Map.entry("nc", "Netcat command"),
            Map.entry("nmap", "Network scanning"),
            Map.entry("iptables", "Firewall modification"),
            Map.entry("useradd", "User creation"),
            Map.entry("userdel", "User deletion"),
            Map.entry("visudo", "Sudoers file modification"),
            Map.entry("crontab", "Scheduled task modification"),
            Map.entry("kill", "Process termination")
    );

    //Danh sách các mẫu lệnh đáng ngờ
    private static final Map<String, String> SUSPICIOUS_PATTERNS = Map.of(
            ".*\\|.*bash", "Possible command injection",
            ".*>.*/dev/tcp/", "Possible reverse shell",
            ".*\\$\\{.*\\}.*", "Possible command injection",
            ".*\\(\\s*\\)\\s*\\{.*", "Possible shell function definition",
            ".*echo.*\\|.*sh", "Possible command injection",
            ".*wget.*-O.*sh", "Possible malicious script download",
            ".*curl.*\\|.*sh", "Possible malicious script download",
            ".*chmod.*\\+x", "Making file executable",
            ".*/bin/bash.*-i", "Possible interactive shell",
            ".*ssh.*-o.*StrictHostKeyChecking=no", "SSH with disabled host key checking"
    );

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
    public String getUserInfo(@RequestParam("host") String host, Model model, HttpSession session) {
        if (session.getAttribute("user") == null) {
            return "redirect:/";
        }
        Map<String, Object> server = jdbcTemplate.queryForMap("SELECT * FROM servers WHERE host = ?", host);
        model.addAttribute("server", server);
        return "user-management";
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

    @PostMapping(value = "/api/manage-user", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> manageUser(
            @RequestParam("host") String host,
            @RequestParam("action") String action,
            @RequestParam("username") String username,
            @RequestParam(value = "password", required = false) String password,
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

            String command;
            String successMessage;

            if ("linux".equalsIgnoreCase(osType)) {
                switch (action) {
                    case "add":
                        command = String.format("echo '%s' | sudo -S adduser --disabled-password --gecos '' %s && echo '%s:%s' | sudo -S chpasswd && echo '%s' | sudo -S chage -d 0 %s",
                                sudoPassword, username, username, password, sudoPassword, username);
                        successMessage = "User added successfully with password expiration";
                        break;
                    case "delete":
                        command = String.format("echo '%s' | sudo -S userdel -r %s",
                                sudoPassword, username);
                        successMessage = "User deleted successfully";
                        break;
                    case "lock":
                        command = String.format("echo '%s' | sudo -S passwd -l %s",
                                sudoPassword, username);
                        successMessage = "User locked successfully";
                        break;
                    case "unlock":
                        command = String.format("echo '%s' | sudo -S passwd -u %s",
                                sudoPassword, username);
                        successMessage = "User unlocked successfully";
                        break;
                    case "add_to_sudo":
                        command = String.format("echo '%s' | sudo -S usermod -aG sudo %s",
                                sudoPassword, username);
                        successMessage = "User added to sudo group";
                        break;
                    case "remove_from_sudo":
                        command = String.format("echo '%s' | sudo -S deluser %s sudo",
                                sudoPassword, username);
                        successMessage = "User removed from sudo group";
                        break;
                    case "reset_password":
                        command = String.format("echo '%s' | sudo -S bash -c \"echo '%s:%s' | chpasswd && chage -d 0 %s\"",
                                sudoPassword, username, password, username);
                        successMessage = "Password reset successfully with expiration";
                        break;
                    case "check_password_age":
                        command = String.format("echo '%s' | sudo -S chage -l %s | grep 'Last password change'",
                                sudoPassword, username);
                        return ResponseEntity.ok(Map.of("output", conn.CommandExec(command)));
                    default:
                        return ResponseEntity.badRequest().body(Map.of("error", "Invalid action"));
                }

            } else {
                switch (action) {
                    case "add":
                        command = "net user " + username + " " + password + " /add";
                        successMessage = "User added successfully";
                        break;
                    case "delete":
                        command = "net user " + username + " /delete";
                        successMessage = "User deleted successfully";
                        break;
                    case "lock":
                        command = "net user " + username + " /active:no";
                        successMessage = "User locked successfully";
                        break;
                    case "unlock":
                        command = "net user " + username + " /active:yes";
                        successMessage = "User unlocked successfully";
                        break;
                    case "add_to_sudo":
                        command = "net localgroup Administrators " + username + " /add";
                        successMessage = "User added to Administrators group";
                        break;
                    case "remove_from_sudo":
                        command = "net localgroup Administrators " + username + " /delete";
                        successMessage = "User removed from Administrators group";
                        break;
                    case "reset_password":
                        command = "net user " + username + " " + password + "";
                        successMessage = "Password reset successfully";
                        break;
                    case "check_password_age":
                        command = "net user " + username + "";
                        return ResponseEntity.ok(Map.of("output", conn.CommandExec(command)));
                    default:
                        return ResponseEntity.badRequest().body(Map.of("error", "Invalid action"));
                }
            }

            String output = conn.CommandExec(command);
            return ResponseEntity.ok(Map.of("message", successMessage, "output", output));

        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Error managing user: " + e.getMessage()));
        }
    }

    @GetMapping(value = "/api/user-info", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getUserInfo(@RequestParam("host") String host, HttpSession session) {
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
                futures.put("current_user", execAsync(conn, "whoami"));
                futures.put("all_users", execAsync(conn, "awk -F: '($3 >= 1000 && $3 < 65534 && $7 !~ /nologin|false/)' /etc/passwd"));
                futures.put("active_users", execAsync(conn, "w -h | awk '{print $1}' | sort | uniq"));
                futures.put("sudo_users", execAsync(conn, "getent group sudo | awk -F: '{print $4}' | tr ',' '\\n' | sed '/^$/d'"));
                futures.put("locked_accounts", execAsync(conn, "echo '" + sudoPassword + "' | sudo -S getent shadow | awk -F: '$2 ~ /^!/ {print $1}' | while read user; do [ -d \"/home/$user\" ] && echo \"$user\"; done"));
                futures.put("last_logins", execAsync(conn,
                        "for user in $(awk -F: '$6 ~ /^\\/home\\// {print $1}' /etc/passwd); do "
                        + "lastlog -u \"$user\" | tail -n 1 | awk -v u=\"$user\" '{if ($0 ~ /Never/) print u\": Never\"; else print u\": \"$4\" \"$5\" \"$6\" \"$7}' ; "
                        + "done"
                ));
            } else {
                futures.put("current_user", execAsync(conn, "powershell -Command \"(whoami) -split '\\\\' | Select-Object -Last 1\""));
                futures.put("all_users", execAsync(conn,
                        "powershell -Command \""
                        + "Get-LocalUser | Where-Object { $_.Name -ne 'DefaultAccount' -and $_.Name -ne 'Guest' -and $_.Name -ne 'WDAGUtilityAccount' } | "
                        + "ForEach-Object { $_.Name }\""
                ));
                futures.put("active_users", execAsync(conn, "powershell -command \"Get-LocalUser | Where-Object {$_.Enabled -eq $true} | Select-Object Name\""));
                futures.put("sudo_users", execAsync(conn, "powershell -command \"Get-LocalGroupMember Administrators | ForEach-Object { ($_ -split '\\\\')[1] }\""));
                futures.put("locked_accounts", execAsync(conn, "powershell -command \"Get-LocalUser | Where-Object { $_.Enabled -eq $false -and $_.SID -match '-1\\d{3,}$' } | Select-Object -ExpandProperty Name\""));
                futures.put("last_logins", execAsync(conn,
                        "powershell -command \"Get-LocalUser | ForEach-Object { "
                        + "$user = $_.Name; "
                        + "$lastLogon = if ($_.LastLogon) { $_.LastLogon } else { 'Never' }; "
                        + "Write-Output \\\"${user}: $lastLogon\\\"} "
                ));
            }
            for (Map.Entry<String, Future<String>> entry : futures.entrySet()) {
                result.put(entry.getKey(), entry.getValue().get());
            }

            saveToJsonFile(host, result, "user_");
            return ResponseEntity.ok(result);

        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Could not get user information: " + e.getMessage()));
        }
    }

    @GetMapping(value = "/api/user-details", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getUserDetails(
            @RequestParam("host") String host,
            @RequestParam("username") String username,
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

            Map<String, String> commands = new HashMap<>();
            Map<String, Future<String>> futures = new HashMap<>();

            if ("linux".equalsIgnoreCase(osType)) {
                futures.put("basic_info", execAsync(conn,
                        "getent passwd " + username + " | awk -F: 'BEGIN { OFS=\"\" } "
                        + "{ print \"Username:       \" $1; print \"UID:            \" $3; print \"GID:            \" $4; "
                        + "print \"Full Name:      \" $5; print \"Shell:          \" $7 }' && "
                        + "echo '" + sudoPassword + "' | sudo -S getent shadow " + username + " | awk -F: '{ print \"Password Hash:  \" $2 }' && "
                        + "ls -ld --time=ctime /home/" + username + " | awk '{ print \"Created Date:    \" $6, $7, $8 }'"
                ));
                commands.put("last_login", "last -n 5 " + username + " | grep -v 'wtmp begins'");
                commands.put("password_expiry", "echo '" + sudoPassword + "' | sudo -S chage -l " + username);
                commands.put("home_dir", "getent passwd " + username + " | awk -F: '{ print $6; }'");
                commands.put("groups", "groups " + username + " | cut -d ':' -f2");
                commands.put("processes", "ps -u " + username + " 2>/dev/null");
                commands.put("disk_usage", "du -sh ~" + username + " 2>/dev/null || echo ''");
                commands.put("sudo_access", "groups " + username + " | grep -q sudo && echo \"Yes\" || echo \"No\"");
                commands.put("status_access", "echo '" + sudoPassword + "' | sudo -S passwd -S " + username);
            } else {
                commands.put("basic_info", "net user " + username);
                commands.put("last_login", "powershell -command \"Get-EventLog -LogName Security -InstanceId 4624 -Newest 5 | Where-Object {$_.Message -match '" + username + "'} | Select-Object TimeGenerated,Message\"");
                commands.put("password_expiry",
                        "powershell -Command \""
                        + "$user = Get-LocalUser -Name '" + username + "'; "
                        + "if ($user) { "
                        + "$pls = if ($null -ne $user.PasswordLastSet) { $user.PasswordLastSet } else { 'False' }; "
                        + "$pexp = if ($null -ne $user.PasswordExpires) { $user.PasswordExpires } else { 'False' }; "
                        + "$mayChange = if ($null -ne $user.UserMayChangePassword) { $user.UserMayChangePassword } else { 'False' }; "
                        + "$required = if ($null -ne $user.PasswordRequired) { $user.PasswordRequired } else { 'False' }; "
                        + "$enabled = if ($null -ne $user.Enabled) { $user.Enabled } else { 'False' }; "
                        + "$locked = if ($null -ne $user.LockedOut) { $user.LockedOut } else { 'False' }; "
                        + "Write-Output ('PasswordLastSet=' + $pls); "
                        + "Write-Output ('PasswordExpires=' + $pexp); "
                        + "Write-Output ('UserMayChangePassword=' + $mayChange); "
                        + "Write-Output ('PasswordRequired=' + $required); "
                        + "Write-Output ('Enabled=' + $enabled); "
                        + "Write-Output ('LockedOut=' + $locked) "
                        + "} else { Write-Output 'User not found' }\""
                );

                commands.put("home_dir", "powershell -command \"if (Test-Path ('C:\\Users\\" + username + "')) { Get-ChildItem -Path 'C:\\Users\\" + username + "' } else { 'Home directory not found' }\"");
                commands.put("groups", "powershell -command \"(net user " + username + ") -match 'Group Memberships' | ForEach-Object { ($_ -replace '.*Memberships\\s+', '').Trim().Split(' ') } | ForEach-Object { $_.Trim() -replace '^\\*', '' } | Where-Object { $_ -ne '' }\"");
                commands.put("processes", "powershell -command \"Get-Process -IncludeUserName | Where-Object {$_.UserName -match '" + username + "'} | Select-Object ProcessName,Id,CPU -First 10\"");
                commands.put("disk_usage",
                        "powershell -command \"if (Test-Path ('C:\\Users\\" + username + "')) { "
                        + "$size = (Get-ChildItem -Path 'C:\\Users\\" + username + "' -Recurse | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum / 1MB; "
                        + "[math]::Round($size, 2).ToString() + ' MB' } "
                        + "else { 'N/A' }\""
                );
                commands.put("sudo_access", "powershell -command \"if ((Get-LocalGroupMember Administrators | Where-Object {$_.Name -match '" + username + "'}).Count -gt 0) { 'Yes' } else { 'No' }\"");
                commands.put("status_access",
                        "powershell -Command \""
                        + "$user = Get-LocalUser -Name '" + username + "'; "
                        + "if ($user) { "
                        + "$enabled = if ($null -ne $user.Enabled) { $user.Enabled } else { 'False' }; "
                        + "$lockedOut = if ($null -ne $user.LockedOut) { $user.LockedOut } else { 'False' }; "
                        + "Write-Output ('Enabled=' + $enabled + '; LockedOut=' + $lockedOut) "
                        + "} else { Write-Output 'User not found' }\""
                );

            }

            for (Map.Entry<String, String> entry : commands.entrySet()) {
                futures.put(entry.getKey(), execAsync(conn, entry.getValue()));
            }

            Map<String, Object> result = new HashMap<>();
            for (Map.Entry<String, Future<String>> entry : futures.entrySet()) {
                result.put(entry.getKey(), entry.getValue().get());
            }

            return ResponseEntity.ok(result);

        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Could not get user details: " + e.getMessage()));
        }
    }

    @GetMapping(value = "/api/command-history", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getCommandHistory(
            @RequestParam("host") String host,
            @RequestParam("username") String username,
            HttpSession session) {

        if (session.getAttribute("user") == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
        }

        try {
            Map<String, Connect> Connects = (Map<String, Connect>) session.getAttribute("connectMap");
            Connect conn = Connects != null ? Connects.get(host) : null;

            if (conn == null || !conn.isConnected()) {
                return ResponseEntity.status(400).body(Map.of("error", "Not connected to server"));
            }

            Map<String, Object> server = jdbcTemplate.queryForMap("SELECT * FROM servers WHERE host = ?", host);
            String osType = (String) server.get("os_type");
            String sudoPassword = (String) server.get("password");
            boolean isAdmin = checkIfAdmin(conn, osType, username, sudoPassword);

            String command;
            if ("linux".equalsIgnoreCase(osType)) {
                command = String.format(
                        "echo '%s' | sudo -S -u %s cat /home/%s/.bash_history 2>/dev/null || "
                        + "echo '%s' | sudo -S grep -a '%s' /home/%s/.bash_history 2>/dev/null || "
                        + "echo 'No command history found'",
                        sudoPassword, username, username,
                        sudoPassword, username, username
                );
            } else {
                command = "powershell -command \"$historyPath = Join-Path $env:APPDATA 'Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt'; "
                        + "if (Test-Path $historyPath) { Get-Content $historyPath -Tail 50 } "
                        + "else { 'No PSReadLine history found' }\"";
            }

            String output = conn.CommandExec(command);
            List<String> commands = Arrays.asList(output.split("\n"));

            // Phân tích lịch sử lệnh
            Map<String, Object> analysis = analyzeCommandHistory(commands, isAdmin, username);

            return ResponseEntity.ok(Map.of(
                    "commands", commands,
                    "count", commands.size(),
                    "raw_output", output,
                    "analysis", analysis,
                    "is_admin", isAdmin
            ));

        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Could not get command history: " + e.getMessage()));
        }
    }

    private boolean checkIfAdmin(Connect conn, String osType, String username, String sudoPassword) throws Exception {
        if ("linux".equalsIgnoreCase(osType)) {
            String command = String.format("echo '%s' | sudo -S groups %s | grep -q sudo && echo true || echo false",
                    sudoPassword, username);
            String result = conn.CommandExec(command).trim();
            return "true".equals(result);
        } else {
            String command = String.format("powershell -command \"(Get-LocalGroupMember -Group 'Administrators' | "
                    + "Select-Object -ExpandProperty Name | ForEach-Object { ($_ -split '\\\\')[1] }) -contains '%s'\"",
                    username);
            String result = conn.CommandExec(command).trim();
            return "True".equalsIgnoreCase(result);
        }
    }

    private Map<String, Object> analyzeCommandHistory(List<String> commands, boolean isAdmin, String username) {
        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> classifiedCommands = new ArrayList<>();
        List<Map<String, Object>> warnings = new ArrayList<>();
        Map<String, Integer> commandFrequency = new HashMap<>();

        // Phân loại lệnh và kiểm tra bất thường
        for (String cmd : commands) {
            if (cmd == null || cmd.trim().isEmpty()) {
                continue;
            }

            String trimmedCmd = cmd.trim();
            Map<String, Object> commandInfo = new HashMap<>();
            commandInfo.put("command", trimmedCmd);
            commandInfo.put("timestamp", "");

            // Kiểm tra lệnh nguy hiểm
            for (Map.Entry<String, String> entry : DANGEROUS_COMMANDS.entrySet()) {
                if (trimmedCmd.startsWith(entry.getKey())) {
                    commandInfo.put("danger_level", "high");
                    commandInfo.put("category", "dangerous");
                    commandInfo.put("description", entry.getValue());

                    // Thêm cảnh báo nếu người dùng không phải admin
                    if (!isAdmin) {
                        warnings.add(createWarning(
                                "Dangerous command by non-admin user",
                                "User " + username + " executed dangerous command: " + trimmedCmd,
                                "high"
                        ));
                    }
                    break;
                }
            }

            // Kiểm tra mẫu đáng ngờ
            for (Map.Entry<String, String> entry : SUSPICIOUS_PATTERNS.entrySet()) {
                if (trimmedCmd.matches(entry.getKey())) {
                    commandInfo.put("danger_level", "medium");
                    commandInfo.put("category", "suspicious");
                    commandInfo.put("description", entry.getValue());
                    warnings.add(createWarning(
                            "Suspicious command pattern",
                            "User " + username + " executed suspicious command: " + trimmedCmd,
                            "medium"
                    ));
                    break;
                }
            }

            // Kiểm tra cố gắng leo quyền
            if (!isAdmin && (trimmedCmd.startsWith("sudo ") || trimmedCmd.startsWith("su "))) {
                commandInfo.put("danger_level", "critical");
                commandInfo.put("category", "privilege_escalation");
                commandInfo.put("description", "Possible privilege escalation attempt");
                warnings.add(createWarning(
                        "Privilege escalation attempt",
                        "Non-admin user " + username + " attempted privilege escalation: " + trimmedCmd,
                        "critical"
                ));
            }

            // Đếm tần suất lệnh
            String baseCmd = trimmedCmd.split(" ")[0];
            commandFrequency.put(baseCmd, commandFrequency.getOrDefault(baseCmd, 0) + 1);

            classifiedCommands.add(commandInfo);
        }

        // Kiểm tra lệnh được dùng quá nhiều lần
        for (Map.Entry<String, Integer> entry : commandFrequency.entrySet()) {
            if (entry.getValue() > 5) { // Ngưỡng 5 lần
                warnings.add(createWarning(
                        "Frequent command usage",
                        "Command '" + entry.getKey() + "' was used " + entry.getValue() + " times by " + username,
                        "low"
                ));
            }
        }

        result.put("classified_commands", classifiedCommands);
        result.put("warnings", warnings);
        result.put("command_frequency", commandFrequency);
        result.put("total_warnings", warnings.size());

        return result;
    }

    private Map<String, Object> createWarning(String title, String message, String severity) {
        Map<String, Object> warning = new HashMap<>();
        warning.put("title", title);
        warning.put("message", message);
        warning.put("severity", severity);
        warning.put("timestamp", System.currentTimeMillis());
        return warning;
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

    @GetMapping(value = "/api/user-info/readFile", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getUserInfoFromFile(
            @RequestParam("host") String host,
            HttpSession session) {

        if (session.getAttribute("user") == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
        }

        Map<String, Object> userInfo = readFile(host, "user_");
        if (userInfo != null) {
            return ResponseEntity.ok(userInfo);
        } else {
            return ResponseEntity.status(404)
                    .body(Map.of("error", "File not found or could not be read"));
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

    @GetMapping(value = "/api/active-users-details", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getActiveUsersDetails(
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
                futures.put("active_users_details", execAsync(conn, "echo '" + sudoPassword + "' | sudo -S w"));
                futures.put("active_processes", execAsync(conn, "echo '" + sudoPassword + "' | sudo -S ps aux | head -n 10"));
                futures.put("system_resources", execAsync(conn, "echo '" + sudoPassword + "' | sudo -S top -bn1 | head -n 5"));
                futures.put("locked_accounts_details", execAsync(conn,
                        "echo '" + sudoPassword + "' | sudo -S bash -c \"(echo 'Username Status Last_Change'; passwd -S -a | grep ' L ') | column -t\""));
                futures.put("admin_users", execAsync(conn, "getent group sudo | cut -d: -f4"));
            } else {
                futures.put("active_users_details", execAsync(conn,
                        "powershell -command \"Get-LocalUser | Where-Object {$_.Enabled -eq $true} | "
                        + "Select-Object Name, Description, LastLogon | "
                        + "Format-Table -AutoSize | Out-String\""));
                futures.put("active_processes", execAsync(conn,
                        "powershell -command \"Get-Process | Select-Object ProcessName,Id,CPU,WorkingSet -First 10 | "
                        + "Format-Table -AutoSize | Out-String\""));
                futures.put("system_resources", execAsync(conn,
                        "powershell -command \"Get-Counter '\\Processor(_Total)\\% Processor Time','\\Memory\\Available MBytes' | "
                        + "Select-Object -ExpandProperty CounterSamples | "
                        + "Select-Object Path,CookedValue | Format-Table -AutoSize | Out-String\""));
                futures.put("locked_accounts_details", execAsync(conn,
                        "powershell -command \"Get-LocalUser | Where-Object {$_.Enabled -eq $false} | "
                        + "Select-Object Name, FullName, Description, LastLogon | "
                        + "Format-Table -AutoSize | Out-String\""));
                futures.put("admin_users", execAsync(conn,
                        "powershell -command \"Get-LocalGroupMember -Group 'Administrators' | "
                        + "Select-Object Name, ObjectClass, PrincipalSource | "
                        + "Format-Table -AutoSize | Out-String\""));
            }

            for (Map.Entry<String, Future<String>> entry : futures.entrySet()) {
                result.put(entry.getKey(), entry.getValue().get());
            }

            return ResponseEntity.ok(result);

        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Could not get active users details: " + e.getMessage()));
        }
    }

}
