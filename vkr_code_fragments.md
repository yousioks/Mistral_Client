# ПРИЛОЖЕНИЕ Г
## Фрагменты программной реализации модулей защиты Mistral SOC

---

### 1. Фрагмент класса управления белыми списками (Whitelist Manager)

Данный класс `WhitelistManager` на сервере Node.js отвечает за динамическое формирование белого списка сетевых адресов (IP и CIDR подсетей). Он автоматически исключает из возможных блокировок локальные адреса (loopback), адреса хостов активных SSH-сессий (определяемые через переменные окружения и утилиту `who`), а также IP-адреса, с которых в данный момент подключены веб-клиенты операторов безопасности SOC.

```javascript
class WhitelistManager {
  constructor() {
    this.staticWhitelist = BANNED_IP_WHITELIST; // Набор статических IP (Set)
    this.cidrWhitelist = BANNED_IP_WHITELIST_CIDRS; // Набор CIDR диапазонов (Set)
    this.activeSshSessions = ACTIVE_SSH_SESSIONS; // Активные сессии SSH (Set)
  }

  // Проверка валидности формата IPv4 или IPv6 адреса
  isValidIp(ip) {
    if (typeof ip !== "string") return false;
    const trimmed = ip.trim();
    const ipv4Pattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Pattern = /^(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}$|^(?:[A-Fa-f0-9]{1,4}:){1,7}:$|^:(?::[A-Fa-f0-9]{1,4}){1,7}$|^(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}$/;
    return ipv4Pattern.test(trimmed) || ipv6Pattern.test(trimmed);
  }

  // Проверка валидности формата IP-адреса или подсети CIDR
  isValidIpOrCidr(val) {
    if (typeof val !== "string") return false;
    const trimmed = val.trim();
    const cidrPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:3[0-2]|[12]?[0-9])$|^[A-Fa-f0-9:]+\/(?:12[0-8]|1[01][0-9]|[1-9]?[0-9])$/;
    return this.isValidIp(trimmed) || cidrPattern.test(trimmed);
  }

  // Проверка возможности применения блокировки (запрет бана доверенных IP)
  isIpBannable(ip) {
    if (!ip) return false;
    
    const normalizedTarget = ip.replace(/^::ffff:/, "").trim().toLowerCase();
    
    // Защита от блокировки локального интерфейса (Loopback)
    if (
      normalizedTarget === "127.0.0.1" || 
      normalizedTarget === "localhost" || 
      normalizedTarget === "::1" || 
      normalizedTarget === "0.0.0.0" || 
      normalizedTarget === "::" ||
      normalizedTarget.startsWith("127.")
    ) {
      logger.info(`[IP-Blocker] Block skipped: 127.0.0.1/loopback cannot be banned.`);
      return false;
    }
    
    // Проверка нахождения в статическом белом списке
    if (this.staticWhitelist.has(normalizedTarget)) {
      logger.info(`IP Ban skipped: ${ip} is whitelisted (unbannable list / active SSH connection)`);
      return false;
    }

    // Проверка соответствия белым диапазонам подсетей CIDR
    for (const cidr of this.cidrWhitelist) {
      if (ipInCidr(normalizedTarget, cidr)) {
        logger.info(`IP Ban skipped: ${ip} matches whitelisted CIDR range: ${cidr}`);
        return false;
      }
    }
    
    // Предотвращение блокировки активных операторов Desktop UI (защита от lockout)
    const connectedIps = Array.from(clients.values()).map(c => c.ip ? c.ip.replace(/^::ffff:/, "").trim() : "");
    if (connectedIps.includes(normalizedTarget)) {
      logger.warn(`IP Ban skipped: ${ip} is associated with an active operator session to prevent lockout.`);
      return false;
    }
    
    return true;
  }

  // Обновление белых списков на основе конфигурации и SSH-сессий хоста
  updateSshAndFileWhitelist() {
    const os = require("os");
    const fs = require("fs");
    const { exec } = require("child_process");

    logger.info("[IP-Whitelist] Initializing IP exclusions & connected SSH devices whitelist...");

    // Чтение статического белого списка из JSON-файла исключений
    const whitelistFile = path.join(__dirname, "..", "data", "unbannable_ips.json");
    if (fs.existsSync(whitelistFile)) {
      try {
        const fileIps = JSON.parse(fs.readFileSync(whitelistFile, "utf8"));
        fileIps.forEach(item => {
          if (typeof item === "string" && item.trim()) {
            const trimmed = item.trim().toLowerCase();
            if (trimmed.includes("/")) {
              this.cidrWhitelist.add(trimmed);
            } else {
              this.staticWhitelist.add(trimmed);
            }
          }
        });
        logger.info(`[IP-Whitelist] Loaded ${fileIps.length} static IP/CIDR exclusions from ${whitelistFile}`);
      } catch (e) {
        logger.error(`[IP-Whitelist] Failed to parse whitelist exclusions: ${e.message}`);
      }
    }

    // Автоматический белый список адреса запуска сессии
    const sshConnection = process.env.SSH_CONNECTION || process.env.SSH_CLIENT;
    if (sshConnection) {
      const parts = sshConnection.trim().split(/\s+/);
      const clientIp = parts[0];
      if (clientIp) {
        const cleanIp = clientIp.replace(/^::ffff:/, "");
        this.staticWhitelist.add(cleanIp);
        this.activeSshSessions.add(cleanIp);
      }
    }

    // Парсинг вывода команды 'who' для сбора IP-адресов текущих терминалов
    exec("who", (err, stdout) => {
      if (!err && stdout) {
        const lines = stdout.split("\n");
        lines.forEach(line => {
          const match = line.match(/\(([^)]+)\)/);
          if (match) {
            const ip = match[1].trim();
            if (ip && !ip.startsWith(":") && (ip.includes(".") || ip.includes(":"))) {
              const cleanIp = ip.replace(/^::ffff:/, "");
              this.staticWhitelist.add(cleanIp);
              this.activeSshSessions.add(cleanIp);
            }
          }
        });
      }
    });
  }
}
```

---

### 2. Фрагмент программной реализации подсистемы Startup Active Defense (контроль целостности и ограничение прав)

Данная подсистема решает две задачи при запуске сервера:
1. **Контроль целостности и ограничение прав доступа (`auditSelfPermissions`)**: вычисляет криптографические контрольные суммы файлов конфигурации (SHA-256) и сверяет их с эталоном. В среде Linux принудительно ограничивает права доступа к конфиденциальным файлам (до `0600` — только чтение и запись владельцу), предотвращая чтение секретов другими пользователями ОС.
2. **Аудит безопасности хоста (`performStartupHardeningAudit`)**: проверяет статус межсетевого экрана (UFW), анализирует небезопасные конфигурации SSH (например, `PermitRootLogin yes`) и параметры ядра sysctl (ASLR, ptrace scope, пересылку пакетов), немедленно создавая инциденты безопасности при отклонениях от эталонного состояния.

```javascript
// Модуль контроля целостности агента и ограничения прав на конфигурационные файлы
function auditSelfPermissions() {
  const os = require("os");
  const fs = require("fs");
  const crypto = require("crypto");
  
  // Файлы, критичные для работы и безопасности SOC-сервера
  const targetFiles = [
    path.join(__dirname, "..", ".env"),
    path.join(__dirname, "..", "data", "soar_settings.json"),
    path.join(__dirname, "db.js"),
    path.join(__dirname, "server.js")
  ];

  logger.info("[Self-Protection] Auditing configuration & agent file integrity...");

  const integrityPath = path.join(__dirname, "..", "data", "integrity_hashes.json");
  let integrityHashes = {};
  if (fs.existsSync(integrityPath)) {
    try {
      integrityHashes = JSON.parse(fs.readFileSync(integrityPath, "utf8"));
    } catch (e) {
      logger.error("Failed to read integrity hashes", { err: e.message });
    }
  }

  let hashesChanged = false;

  targetFiles.forEach(filepath => {
    if (!fs.existsSync(filepath)) return;
    const filename = path.basename(filepath);

    // 1. Ограничение прав доступа (Unix Permissions Lockdown)
    if (os.platform() !== "win32") {
      try {
        const stats = fs.statSync(filepath);
        const mode = stats.mode;
        // Если группа или другие пользователи имеют права на чтение/запись/исполнение (маска 077)
        if ((mode & 0o077) !== 0) {
          logger.warn(`[Self-Protection] Insecure permissions detected on ${filename}. Locking down to 0600...`);
          fs.chmodSync(filepath, 0o600); // 0600 - права чтения/записи владельцу
          addIncident(
            "HIGH",
            "SelfProtection",
            "INSECURE_FILE_PERMISSIONS",
            `Обнаружены небезопасные права доступа на критический файл: ${filename}. Права автоматически изменены на 0600.`,
            { filepath, originalMode: (mode & 0o777).toString(8), correctedMode: "600" }
          );
        }
      } catch (e) {
        logger.error(`[Self-Protection] Failed to correct permissions for ${filepath}: ${e.message}`);
      }
    }

    // 2. Контроль целостности на основе хэш-сумм (SHA-256)
    try {
      const fileBuffer = fs.readFileSync(filepath);
      const hash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
      
      const oldHash = integrityHashes[filename];
      if (!oldHash) {
        integrityHashes[filename] = hash;
        hashesChanged = true;
        logger.info(`[Self-Protection] Saved baseline hash for ${filename}`);
      } else if (oldHash !== hash) {
        logger.warn(`[Self-Protection] File integrity violation detected for ${filename}!`);
        addIncident(
          "CRITICAL",
          "SelfProtection",
          "SELF_TAMPERING_ATTEMPT",
          `НАРУШЕНИЕ ЦЕЛОСТНОСТИ АГЕНТА! Обнаружено изменение содержимого файла ${filename}.`,
          { filepath, oldHash, newHash: hash }
        );
        integrityHashes[filename] = hash;
        hashesChanged = true;
      }
    } catch (e) {
      logger.error(`[Self-Protection] Failed to verify integrity hash for ${filepath}: ${e.message}`);
    }
  });

  if (hashesChanged) {
    try {
      fs.writeFileSync(integrityPath, JSON.stringify(integrityHashes, null, 2), "utf8");
    } catch (e) {
      logger.error("Failed to save integrity hashes", { err: e.message });
    }
  }
}

// Запуск первичного аудита защищенности хоста и проверка ядра sysctl
function performStartupHardeningAudit() {
  const os = require("os");
  const fs = require("fs");
  const { exec } = require("child_process");
  logger.info("[Startup Audit] Running Host Hardening compliance check...");

  // Контроль прав и хэш-сумм файлов агента
  auditSelfPermissions();
  
  if (os.platform() === "linux") {
    // Аудит состояния межсетевого экрана (UFW)
    exec("sudo ufw status", (err, stdout) => {
      if (err || !stdout.includes("Status: active")) {
        addIncident(
          "HIGH",
          "StartupAudit",
          "FIREWALL_DISABLED",
          "Внимание: Брандмауэр UFW отключен на хосте. Все входящие порты открыты!",
          { reason: "UFW is inactive. Recommended mitigation: run 'sudo ufw enable'." }
        );
      }
    });

    // Аудит конфигурации безопасности SSH-демона
    if (fs.existsSync("/etc/ssh/sshd_config")) {
      try {
        const sshConf = fs.readFileSync("/etc/ssh/sshd_config", "utf8");
        if (sshConf.match(/^\s*PermitRootLogin\s+yes/m)) {
          addIncident(
            "HIGH",
            "StartupAudit",
            "SSH_INSECURE_CONFIGURATION",
            "Конфигурация SSH: Разрешен вход суперпользователя Root по паролю (PermitRootLogin yes)",
            { recommendation: "Change PermitRootLogin to 'no' in /etc/ssh/sshd_config." }
          );
        }
      } catch (e) {
        logger.error("[Startup Audit] Failed to read SSH config", { err: e.message });
      }
    }

    // Аудит укрепления параметров ядра Linux (Hardening sysctl)
    const sysctlChecks = [
      { path: "/proc/sys/kernel/randomize_va_space", expected: "2", type: "ASLR_DISABLED", desc: "Рандомизация адресного пространства (ASLR) отключена." },
      { path: "/proc/sys/kernel/yama/ptrace_scope", expected: "1", type: "PTRACE_SCOPE_INSECURE", desc: "Небезопасный доступ ptrace: процессы могут читать память соседних процессов." },
      { path: "/proc/sys/net/ipv4/ip_forward", expected: "0", type: "IP_FORWARDING_ENABLED", desc: "Включена переадресация IP-пакетов (IP Forwarding)." }
    ];

    sysctlChecks.forEach(check => {
      if (fs.existsSync(check.path)) {
        try {
          const value = fs.readFileSync(check.path, "utf8").trim();
          if (value !== check.expected) {
            addIncident(
              "HIGH",
              "KernelHardening",
              check.type,
              `Нарушение безопасности ядра: ${check.desc} (Ожидалось: ${check.expected}, найдено: ${value})`,
              { path: check.path, value, expected: check.expected }
            );
          }
        } catch (e) {
          logger.error(`[Startup Audit] Failed to read kernel param ${check.path}`, { err: e.message });
        }
      }
    });
  }
}
```
