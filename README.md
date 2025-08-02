# ssh-watcher
A real-time SSH session watcher that monitors logins, detects anomalies, and alerts on suspicious activity.


## 🧪 SSH Watcher Test Bed Setup

This guide walks you through setting up a lightweight, SSH-enabled Docker container to simulate SSH activity for development or testing purposes.

---

### 🚀 1. Run an SSH-Enabled Docker Container

```bash
docker run -d -P --name ssh-test rastasheep/ubuntu-sshd:latest
```

- `-d` – Run container in detached mode  
- `-P` – Map container’s ports to random ports on the host  
- `--name ssh-test` – Assign a name to the container  
- `rastasheep/ubuntu-sshd:latest` – Lightweight SSH-enabled image  

---

### 🔍 2. Lookup Port Mapped to Host

```bash
docker port ssh-test 22
```

- This shows the random host port mapped to the container’s port 22 (SSH).

---

### 🔑 3. SSH into the Container

Once you know the host port (say `49154`), connect using:

```bash
ssh root@localhost -p <port-number>
## Example:
ssh root@localhost -p 49154
```

> The default root password is usually `root` (unless changed).  

---

### 📄 4. Check for SSH Logs

To check logs:

```bash
docker exec -it ssh-test bash
```

- Opens an interactive bash shell in the container.

Look for the authentication log:

```bash
cat /var/log/auth.log
```

If not found, follow the steps below to enable logging.

---

### ⚙️ Enable Logging Inside the Container

#### Update & Upgrade System

```bash
apt update
apt upgrade
```

- `apt update` – Fetches latest package info  
- `apt upgrade` – Safely upgrades installed packages (skips if dependencies need to be added/removed)  

To perform a full upgrade:

```bash
apt full-upgrade
```

#### Install Rsyslog (System Logging Daemon)

```bash
apt install rsyslog -y
```

- `-y` – Automatically confirms all prompts

#### Start Rsyslog Service

```bash
service rsyslog start
```

---

### ✅ Verify Rsyslog Is Running

```bash
ps aux | grep rsyslog
```

- `ps` – Process snapshot  
- `a` – Show processes for all users  
- `u` – Show user who owns the process  
- `x` – Include processes not attached to a terminal  
- `grep` – Pattern match for `rsyslog`  

---

### 🔐 5. (Optional) Setup SSH Key-Based Authentication

Using key-based authentication is:

- More secure than password-based login  
- Ideal for scripting and automated testing  
- Recommended for production-like simulations  