# ПРИЛОЖЕНИЕ Г
## Фрагменты программной реализации модулей защиты Mistral SOC

---

### 1. Фрагмент класса управления белыми списками (isIpBannable)

Данный фрагмент содержит ключевую функцию проверки сетевого адреса в классе `WhitelistManager` для предотвращения ложных срабатываний и блокировки доверенных хостов (loopback, статического белого списка, CIDR-подсетей и активных сессий администраторов).

```javascript
class WhitelistManager {
  constructor() {
    this.staticWhitelist = BANNED_IP_WHITELIST; // Набор разрешенных IP
    this.cidrWhitelist = BANNED_IP_WHITELIST_CIDRS; // Набор CIDR подсетей
  }

  // Проверка возможности блокировки IP-адреса
  isIpBannable(ip) {
    if (!ip) return false;
    const normalizedTarget = ip.replace(/^::ffff:/, "").trim().toLowerCase();
    
    // Защита от блокировки локального интерфейса (Loopback)
    if (
      normalizedTarget === "127.0.0.1" || normalizedTarget === "localhost" || 
      normalizedTarget === "::1" || normalizedTarget === "0.0.0.0" || 
      normalizedTarget === "::" || normalizedTarget.startsWith("127.")
    ) {
      return false;
    }
    
    // Проверка наличия адреса в статическом белом списке
    if (this.staticWhitelist.has(normalizedTarget)) {
      return false;
    }

    // Проверка на соответствие белым диапазонам CIDR
    for (const cidr of this.cidrWhitelist) {
      if (ipInCidr(normalizedTarget, cidr)) {
        return false;
      }
    }
    
    // Предотвращение самоблокировки активных сессий операторов SOC
    const connectedIps = Array.from(clients.values()).map(c => c.ip ? c.ip.replace(/^::ffff:/, "").trim() : "");
    if (connectedIps.includes(normalizedTarget)) {
      return false;
    }
    
    return true;
  }
}
```

---

### 2. Фрагмент программной реализации подсистемы Startup Active Defense (auditSelfPermissions)

Данный фрагмент демонстрирует логику контроля целостности исполняемых скриптов агента по контрольным суммам SHA-256 и автоматическое ограничение прав доступа (Lockdown) к критическим конфигурационным файлам в среде UNIX (установка прав `0600`).

```javascript
// Контроль целостности и ограничение прав доступа к критическим файлам
function auditSelfPermissions() {
  const os = require("os");
  const fs = require("fs");
  const crypto = require("crypto");
  
  const targetFiles = [
    path.join(__dirname, "..", ".env"),
    path.join(__dirname, "server.js")
  ];

  targetFiles.forEach(filepath => {
    if (!fs.existsSync(filepath)) return;
    const filename = path.basename(filepath);

    // 1. Ограничение прав доступа (Unix Permissions Lockdown)
    if (os.platform() !== "win32") {
      try {
        const stats = fs.statSync(filepath);
        const mode = stats.mode;
        // Если группа или другие пользователи имеют любые права доступа (маска 0077)
        if ((mode & 0o077) !== 0) {
          fs.chmodSync(filepath, 0o600); // 0600 - только чтение/запись владельцу
          addIncident("HIGH", "SelfProtection", "INSECURE_FILE_PERMISSIONS", 
            `Права доступа файла ${filename} автоматически изменены на 0600.`
          );
        }
      } catch (e) {
        logger.error(`[Self-Protection] Failed to correct permissions: ${e.message}`);
      }
    }

    // 2. Контроль целостности по хэш-суммам SHA-256
    try {
      const fileBuffer = fs.readFileSync(filepath);
      const hash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
      const oldHash = integrityHashes[filename];

      if (!oldHash) {
        integrityHashes[filename] = hash;
      } else if (oldHash !== hash) {
        addIncident("CRITICAL", "SelfProtection", "SELF_TAMPERING_ATTEMPT",
          `НАРУШЕНИЕ ЦЕЛОСТНОСТИ! Обнаружено изменение файла ${filename}.`
        );
        integrityHashes[filename] = hash;
      }
    } catch (e) {
      logger.error(`[Self-Protection] Failed to verify hash: ${e.message}`);
    }
  });
}
```
