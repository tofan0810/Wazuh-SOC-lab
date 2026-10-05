# Security & Secrets Management Rules for Agents

## 1. Absolute Prohibition of Hardcoded Secrets
Agents operating in this workspace must strictly follow these rules:

1. **Zero Hardcoded Credentials:**
   - NEVER embed passwords, API keys, private tokens, bot tokens, auth headers, webhook secret URLs, or private IPs/credentials in source code, scripts, test files, configs, or commit messages.
   - Any sensitive value must strictly be loaded from `.env` or system environment variables.

2. **Safe Fallback Requirements:**
   - In Python, always use:
     ```python
     password = os.getenv("LAB_WINDOWS_PASSWORD", "")
     token = os.getenv("TELEGRAM_BOT_TOKEN", "")
     ```
   - NEVER use actual or dummy passwords in the fallback argument (e.g., `os.getenv("VAR", "password123")` is STRICTLY FORBIDDEN).

3. **Template Placeholders Only:**
   - In configuration templates (`deployment/ossec.conf`, `.env.example`), use only placeholder strings:
     - `YOUR_TELEGRAM_BOT_TOKEN`
     - `YOUR_TELEGRAM_CHAT_ID`
     - `YOUR_VIRUSTOTAL_API_KEY`
     - `YOUR_ABUSEIPDB_API_KEY`
     - `YOUR_JIRA_API_TOKEN`

4. **GitGuardian & Pre-Commit Shield Compliance:**
   - Before proposing or making any changes, ensure no files introduce strings matching Generic Password, High Entropy Secret, or known API key regexes.
   - Do NOT attempt to bypass `ggshield` hooks. Fix the root cause by removing the secret.

5. **Safe Handling of .env:**
   - The `.env` file contains production lab credentials and is strictly ignored in `.gitignore`.
   - Never stage, copy, or print raw `.env` contents to public files or documentation.
