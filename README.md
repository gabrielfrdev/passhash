# PassHash

**PassHash** is a secure, developer-focused CLI tool and library for generating and verifying password hashes. It enforces modern security standards (Argon2id) with strict validation.

## 🔒 Security Features

- **Argon2id Standard**: Enforces **Argon2id** with a minimum of **64 MiB** memory cost.
- **Secure Input**: Prevents password leakage in shell history by refusing CLI arguments.
- **DoS Protection**: Validates input length (Max 4 KiB) and computational costs (Max Threads/Memory).
- **Zero Dependencies**: Lightweight, PHP >= 8.1 only.

## 🚀 Installation

### Global (Quick Use)

```bash
composer global require gabrielfrdev/secure-passhash
```

### Local (Development)

```bash
git clone https://github.com/gabrielfrdev/secure-passhash.git
cd secure-passhash
composer install
```

## 🛠 Usage

### 1. Generating a Hash

PassHash uses secure prompts or pipes. **Passwords are never accepted as arguments.**

**Interactive Mode (Recommended):**

```bash
./bin/passhash hash
# You will be prompted securely to enter the password.
```

**Automation (Pipe):**

```bash
echo "my_super_secret_password" | ./bin/passhash hash
```

**Output:**

```text
✔ Hash generated securely.

Algorithm: Argon2id
Hash:
$argon2id$v=19$m=65536,t=4,p=1$XyZ...
```

### 2. Verifying a Hash

To verify, provide the hash. You will be prompted for the password.

```bash
./bin/passhash verify '$argon2id$v=19$m=65536,t=4,p=1$...'
# Prompt: Enter password to verify:
```

### 3. Inspect Configuration

Check the current security parameters used by the machine.

```bash
./bin/passhash config
```

## 🛡 Security considerations

1. **Shell History**: We explicitly block `passhash hash <password>` to prevent your password from being saved in `.bash_history` or system logs (`ps aux`).
2. **Memory Defaults**: We default to **64 MiB** memory cost. OWASP recommends ~19 MiB, but 64 MiB is chosen for higher resistance against GPU cracking on modern servers.
3. **Windows Users**: On Windows CMD/PowerShell, secure input masking might not work (input visible). Use with caution or in a private environment.

## 🧪 Development & Testing

Run the security test suite:

```bash
composer test
# or
vendor/bin/phpunit
```

## License

MIT
