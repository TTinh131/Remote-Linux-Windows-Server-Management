package com.example.ct491.controllers;

import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
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


@Controller
@SessionAttributes("user")
public class SystemController {

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
        return new HashMap<>();
    }

    @GetMapping("/system-infor")
    public String systeminfor(@RequestParam("host") String host, Model model, HttpSession session) {
        if (session.getAttribute("user") == null) {
            return "redirect:/";
        }
        Map<String, Object> server = jdbcTemplate.queryForMap("SELECT * FROM servers WHERE host = ?", host);
        model.addAttribute("server", server);
        return "system-infor";
    }

    private Future<String> execAsync(Connect conn, String command) {
        return executorService.submit(() -> {
            try {
                return conn.CommandExec(command);
            } catch (Exception e) {
                return "Lỗi khi thực thi lệnh: " + e.getMessage();
            }
        });
    }

    @GetMapping(value = "/api/system-info", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, String>> getSystemInfo(@RequestParam("host") String host, HttpSession session) {
        if (session.getAttribute("user") == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
        }

        try {
            Map<String, Object> server = jdbcTemplate.queryForMap("SELECT * FROM servers WHERE host = ?", host);
            String osType = (String) server.get("os_type");

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

            Map<String, String> result = new HashMap<>();
            Map<String, Future<String>> futures = new HashMap<>();

            if ("linux".equalsIgnoreCase(osType)) {
                //CPU
                futures.put("cpuname", execAsync(conn, "lscpu | grep \"Model name\" | awk -F ': ' '{print $2}'"));
                futures.put("phcores", execAsync(conn, "lscpu | grep \"Core(s) per socket\" | awk '{print $4}'"));
                futures.put("logiccores", execAsync(conn, "lscpu | grep \"CPU(s):\" | head -n 1 | awk '{print $2}'"));
                futures.put("speedcpu", execAsync(conn, "cat /proc/cpuinfo | grep -E \"cpu MHz\" | head -n 4 | awk -F ': ' '{print $2\"MHz\"}'"));
                futures.put("ktcpu", execAsync(conn, "lscpu | grep \"Architecture\"| awk -F ': ' '{print $2}'"));
                futures.put("hscpu", execAsync(conn, "top -bn1 | grep \"%Cpu(s)\" | awk '{print 100 - $8\"%\"}'"));
                //Ram
                futures.put("ramtotal", execAsync(conn, "free -h | grep Mem | awk '{print $2}'"));
                futures.put("ramused", execAsync(conn, "free -b | grep Mem | awk '{printf \"%.2fGi\", $3 / 1073741824}'"));
                futures.put("ramfree", execAsync(conn, "free -h | grep Mem | awk '{print $4}'"));
                futures.put("swaptotal", execAsync(conn, "free -h | grep Swap | awk '{print $2}'"));
                futures.put("swapused", execAsync(conn, "free -h | grep Swap | awk '{print $3}'"));
                //Disk
                futures.put("disktotal", execAsync(conn, "df -h --total | grep total | awk '{print $2}'"));
                futures.put("diskused", execAsync(conn, "df -h --total | grep total | awk '{print $3}'"));
                futures.put("diskfree", execAsync(conn, "df -h --total | grep total | awk '{print $4}'"));
                futures.put("diskfs", execAsync(conn, "df -T | awk '{print $2}' | uniq | grep -v 'Type'"));
                futures.put("disklist", execAsync(conn, "lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE"));
                // Network
                futures.put("ipaddr", execAsync(conn, "hostname -I | awk '{print $1}'"));
                futures.put("gateway", execAsync(conn, "ip route | grep default | awk '{print $3}'"));
                futures.put("dns", execAsync(conn, "grep nameserver /etc/resolv.conf | awk '{print $2}'"));
                futures.put("netspeed", execAsync(conn, "ethtool $(ip route | grep default | awk '{print $5}') | grep Speed | awk '{print $2}'"));
                futures.put("netstat", execAsync(conn, "ss -tuln"));
                //OS
                futures.put("hostname", execAsync(conn, "hostname"));
                futures.put("osinfo", execAsync(conn, "cat /etc/os-release | grep PRETTY_NAME | awk -F '\"' '{print $2}'"));
                futures.put("kernel", execAsync(conn, "uname -r"));
                futures.put("uptime", execAsync(conn, "uptime -p"));
                futures.put("boottime", execAsync(conn, "who -b | awk '{print $3, $4}'"));
                //Security
                futures.put("lastlogins", execAsync(conn, "last -n 10 | grep -v 'reboot'"));
                // Software 
                futures.put("pendingupdates", execAsync(conn, "(apt list --upgradable 2>/dev/null || yum list updates) | grep -v 'Listing...'"));
                futures.put("softwareversions", execAsync(conn, "echo -e \"nginx: $(nginx -v 2>&1)\\nphp: $(php -v | head -1)\\nmysql: $(mysql --version)\""));
                // User 
                futures.put("loggedusers", execAsync(conn, "who -u"));
                futures.put("systemusers", execAsync(conn, "getent passwd | awk -F: '$7 == \"/bin/bash\" {print $1, $3, $7}' | column -t -s:"));
                futures.put("sudoers", execAsync(conn, "getent group sudo | awk -F: '{print $4}' | tr ',' '\\n' | sed '/^$/d'"));
                futures.put("usersessions", execAsync(conn, "w | head -n 22"));
                //chi tiết
                futures.put("cpu_details", execAsync(conn, "lscpu && echo '=====' && cat /proc/cpuinfo"));
                futures.put("ram_details", execAsync(conn, "free -h && echo '=====' && cat /proc/meminfo"));
                futures.put("disk_details", execAsync(conn, "lsblk -o NAME,SIZE,TYPE,MODEL,SERIAL,VENDOR,ROTA,HOTPLUG,MOUNTPOINT,FSTYPE && echo '=====' && df -hT"));
                futures.put("network_details", execAsync(conn, "echo '===INTERFACES===' && ip addr && echo '===ROUTES===' && ip route && echo '===DNS===' && cat /etc/resolv.conf"));
                futures.put("os_details", execAsync(conn, "cat /etc/os-release && hostnamectl"));
                futures.put("security_details", execAsync(conn, "echo '===FIREWALL (ufw)===' && ufw status && echo '===SECURITY UPDATES===' && apt list --upgradable 2>/dev/null | grep security"));
                futures.put("software_details", execAsync(conn, "echo '===INSTALLED PACKAGES===' && dpkg-query -W -f='${Package},${Version}\n'"));
                futures.put("user_details", execAsync(conn, "echo \"=== USERS ===\" && cut -d: -f1 /etc/passwd && echo \"=== SUDO USERS ===\" && getent group sudo && echo \"=== LOGGED IN USERS ===\" && who"));
            } else {
                //CPU
                futures.put("cpuname", execAsync(conn, "powershell -command \"Get-WmiObject Win32_Processor | Select-Object -ExpandProperty Name\""));
                futures.put("phcores", execAsync(conn, "powershell -command \"Get-CimInstance Win32_Processor | Select-Object -ExpandProperty NumberOfCores\""));
                futures.put("logiccores", execAsync(conn, "powershell -command \"(Get-CimInstance Win32_Processor).NumberOfLogicalProcessors\""));
                futures.put("speedcpu", execAsync(conn, "powershell -command \"Get-CimInstance Win32_Processor | Select-Object -ExpandProperty CurrentClockSpeed | ForEach-Object { $_ / 1 } | ForEach-Object { $_.ToString() + 'MHz' }\""));
                futures.put("ktcpu", execAsync(conn, "powershell -command \"[System.Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE')\""));
                futures.put("hscpu", execAsync(conn, "powershell -command \"(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average | ForEach-Object { $_ / 1 } | ForEach-Object { $_.ToString() + '%' }\""));
                //Ram
                futures.put("ramtotal", execAsync(conn, "for /f \"tokens=4,*\" %a in ('systeminfo ^| findstr /C:\"Total Physical Memory\"') do @echo %a %b"));
                futures.put("ramused", execAsync(conn, "powershell -command \"$total = (Get-Counter '\\Memory\\Available Bytes').CounterSamples[0].CookedValue; [math]::Round(( (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory - $total ) /1GB, 2)| ForEach-Object { $_ / 1 } | ForEach-Object { $_.ToString() + ' MB' }\""));
                futures.put("ramfree", execAsync(conn, "powershell -command \"[math]::Round((Get-Counter '\\Memory\\Available Bytes').CounterSamples[0].CookedValue /1GB, 2)| ForEach-Object { $_ / 1 } | ForEach-Object { $_.ToString() + ' MB' }\""));
                futures.put("swaptotal", execAsync(conn, "powershell -command \"Get-CimInstance Win32_PageFileUsage | Measure-Object -Property AllocatedBaseSize -Sum | % { $_.Sum }| ForEach-Object { $_ / 1 }\""));
                futures.put("swapused", execAsync(conn, "powershell -command \"Get-CimInstance Win32_PageFileUsage | Measure-Object -Property CurrentUsage -Sum | % { $_.Sum }\""));
                //Disk
                futures.put("disktotal", execAsync(conn, "powershell -command \"Get-Volume | Where-Object {$_.DriveType -eq 'Fixed'} | Measure-Object -Property Size -Sum | % { [math]::Round($_.Sum /1GB, 2) }| ForEach-Object { $_ / 1 } | ForEach-Object { $_.ToString() + ' GB' }\""));
                futures.put("diskused", execAsync(conn, "powershell -command \"Get-Volume | Where-Object {$_.DriveType -eq 'Fixed'} | Measure-Object -Property SizeRemaining -Sum | % { [math]::Round( ( (Get-Volume | Where-Object {$_.DriveType -eq 'Fixed'} | Measure-Object -Property Size -Sum).Sum - $_.Sum ) /1GB, 2) }| ForEach-Object { $_ / 1 } | ForEach-Object { $_.ToString() + ' GB' }\""));
                futures.put("diskfree", execAsync(conn, "powershell -command \"Get-Volume | Where-Object {$_.DriveType -eq 'Fixed'} | Measure-Object -Property SizeRemaining -Sum | % { [math]::Round($_.Sum /1GB, 2) }| ForEach-Object { $_ / 1 } | ForEach-Object { $_.ToString() + ' GB' }\""));
                futures.put("diskfs", execAsync(conn, "powershell -command \"Get-Volume | Select-Object FileSystem -Unique | % { $_.FileSystem }\""));
                futures.put("disklist", execAsync(conn, "powershell -command \"Get-Disk | Select-Object Number, FriendlyName, Size, HealthStatus | Format-Table\""));
                // Network 
                futures.put("ipaddr", execAsync(conn, "powershell -command \"(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike '*Loopback*'}).IPAddress\""));
                futures.put("gateway", execAsync(conn, "powershell -command \"(Get-NetRoute -DestinationPrefix '0.0.0.0/0').NextHop\""));
                futures.put("dns", execAsync(conn, "powershell -command \"(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike '*Loopback*'}).ServerAddresses\""));
                futures.put("netspeed", execAsync(conn, "powershell -command \"Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object Name, LinkSpeed\""));
                futures.put("netstat", execAsync(conn, "powershell -command \"Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Format-Table\""));
                //OS
                futures.put("hostname", execAsync(conn, "hostname"));
                futures.put("osinfo", execAsync(conn, "powershell -command \"(Get-CimInstance Win32_OperatingSystem).Caption\""));
                futures.put("kernel", execAsync(conn, "powershell -command \"[System.Environment]::OSVersion.Version\""));
                futures.put("uptime", execAsync(conn, "powershell -command \"(Get-CimInstance Win32_OperatingSystem).LastBootUpTime\""));
                futures.put("boottime", execAsync(conn, "powershell -command \"(Get-CimInstance Win32_OperatingSystem).LastBootUpTime\""));
                // Security
                futures.put("lastlogins", execAsync(conn, "powershell -command \"Get-EventLog -LogName Security -InstanceId 4624 -Newest 10 | Select-Object TimeGenerated,Message\""));
                // Software
                futures.put("pendingupdates", execAsync(conn, "powershell -command \"Get-WindowsUpdate -IsInstalled $false | Select-Object Title\""));
                futures.put("softwareversions", execAsync(conn, "powershell -command \"$output = Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName,DisplayVersion | Out-String -Width 1000; ($output -split '[\\r\\n"
                        + //
                        "]+' | Select-Object -First 4) + ($output -split '[\\r\\n"
                        + "]+' | Select-Object -Skip 9) | Out-String\""));
                // User
                futures.put("loggedusers", execAsync(conn, "powershell -command \"query user\""));
                futures.put("systemusers", execAsync(conn, "powershell -command \"Get-LocalUser | Select-Object Name,Enabled,LastLogon\""));
                futures.put("sudoers", execAsync(conn, "powershell -command \"Get-LocalGroupMember Administrators | ForEach-Object { $_.Name.Split('\\')[-1] }\""));
                futures.put("usersessions", execAsync(conn, "powershell -command \"quser\""));
                //chi tiết
                futures.put("cpu_details", execAsync(conn, "powershell -command \"Get-CimInstance Win32_Processor | Format-List *\""));
                futures.put("ram_details", execAsync(conn, "powershell -command \"Get-CimInstance Win32_PhysicalMemory | Format-List *\""));
                futures.put("disk_details", execAsync(conn, "powershell -command \"Get-CimInstance Win32_DiskDrive | Format-List *\""));
                futures.put("network_details", execAsync(conn, "powershell -command \"Get-NetIPConfiguration | Format-List *\""));
                futures.put("os_details", execAsync(conn, "powershell -command \"Get-CimInstance Win32_OperatingSystem | Format-List *\""));
                futures.put("security_details", execAsync(conn, "powershell -command \"Get-NetFirewallProfile; Get-MpComputerStatus; Get-BitLockerVolume\""));
                futures.put("software_details", execAsync(conn, "powershell -command \"Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\Uninstall\\* , HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* |Select-Object DisplayName, DisplayVersion, Publisher, InstallDate\""));
                futures.put("user_details", execAsync(conn, "powershell -command \"Get-LocalUser; Get-LocalGroup; Get-LocalGroupMember -Group \"Administrators\"; quser\""));
            }

            for (Map.Entry<String, Future<String>> entry : futures.entrySet()) {
                result.put(entry.getKey(), entry.getValue().get());
            }
            // Lưu kết quả vào file JSON
            try {
                ObjectMapper objectMapper = new ObjectMapper();
                String jsonResult = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(result);
                
                // Tạo tên file theo host 
                String fileName = "system_" + host + ".json";
                
                // Tạo thư mục temp nếu chưa tồn tại
                Files.createDirectories(Paths.get(TEMP_DIR));
                
                // Ghi kết quả vào file
                Path filePath = Paths.get(TEMP_DIR, fileName);
                try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath.toFile()))) {
                    writer.write(jsonResult);
                }
            } catch (Exception e) {
                System.err.println("Không thể lưu file kết quả: " + e.getMessage());
            }
            return ResponseEntity.ok(result);
            

        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", "Không thể lấy thông tin hệ thống: " + e.getMessage()));
        }
    }
    private Map<String, Object> readFile(String host) {
        try {
            // Tạo đường dẫn file
            String fileName = "system_" + host + ".json";
            Path filePath = Paths.get(TEMP_DIR, fileName);
            // Kiểm tra file tồn tại
            if (!Files.exists(filePath)) {
                System.err.println("File không tồn tại: " + filePath);
                return null;
            }
            // Đọc nội dung file
            String content = new String(Files.readAllBytes(filePath));
            // Chuyển đổi JSON sang Map
            ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.readValue(content, new TypeReference<Map<String, Object>>() {}); 
        } catch (Exception e) {
            System.err.println("Lỗi khi đọc file JSON: " + e.getMessage());
            return null;
        }
    }
    @GetMapping(value = "/api/system-info/readFile", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getSystemInfoFromFile(
            @RequestParam("host") String host, 
            HttpSession session) {
        
        if (session.getAttribute("user") == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Unauthorized"));
        }
        
        Map<String, Object> systemInfo = readFile(host);
        if (systemInfo != null) {
            return ResponseEntity.ok(systemInfo);
        } else {
            return ResponseEntity.status(404)
                    .body(Map.of("error", "Không tìm thấy hoặc không thể đọc file"));
        }
    }
}