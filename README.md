# HACKtiveMQ based on the Ningu (忍具) Framework

**Author:** Garland Glessner  
**License:** [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html)

---

## 🧩 Overview

**Ningu (忍具)** is a modular, plugin-based GUI framework written in Python using PySide6.  
The name "Ningu" (忍具) refers to "ninja tools" in Japanese, and this framework is designed to load and display self-contained GUI components dynamically as separate tabs.

It is ideal for creating toolkits, hacking suites, or internal developer dashboards where functionality is organized in a modular fashion.

---

## 🚀 Features

- 🧱 Modular architecture — just drop `.py` files in the `modules/` directory.
- 🖥️ Dynamic tab-loading based on plugin contents.
- 🎛️ Tabs aligned to the left for a clean UX.
- ✅ Automatic resource cleanup on close (`cleanup()` method support).
- 📛 Extracts program name and version from the script filename (e.g. `ningu-v1.0.0.py`).

---

## 📁 Directory Structure

```

ningu-v1.0.py
modules/

````

---

## 🔧 Usage

### ✅ Requirements

- Python 3.7+
- [PySide6](https://pypi.org/project/PySide6/)

```bash
pip install PySide6
````

### ▶️ Run the App

```bash
python ningu-v1.0.0.py
```

The program will:

1. Load all `.py` files in the `modules/` directory.
2. Expect each module to define a `TabContent` class (subclass of `QWidget`).
3. Display each module in its own tab.

---

## 📦 Module Development

Each module must be a `.py` file inside the `modules/` directory and should export a `TabContent` class.

### Example:

```python
# modules/hello.py
from PySide6.QtWidgets import QWidget, QLabel, QVBoxLayout

TAB_LABEL = "Hello"

class TabContent(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Hello from a module!"))
        self.setLayout(layout)

    def cleanup(self):
        print("Cleaning up Hello module")
```

---

## 🧼 Graceful Shutdown

* Pressing Ctrl-C from the terminal triggers a clean exit.
* If a module defines a `.cleanup()` method, it will be invoked on shutdown.

---

# STOMPscan (Ningu Module) 

> **STOMPscan v1.3.2** – A graphical reconnaissance tool that fingerprints ActiveMQ / Artemis / other STOMP‑speaking brokers from within the modular **Ningu (忍具)** framework.  
> **Part of the [HACKtiveMQ] tool suite** for broker reconnaissance and penetration testing.

---

## ✨ What it does
* **Mass‑scan hosts** (IPv4 or DNS) on a user‑selected port using raw STOMP frames over **TCP or SSL**  
* **Identifies broker version** by hashing server stack‑traces and mapping them to known releases  
* **Detects authentication state** (enabled/disabled) and brute‑tests **default credential pairs** from `stomp-defaults.txt`  
* **Captures server banner** (`server:` line in CONNECTED frame)  
* **Generates SHA‑256 fingerprints** for unknown stack‑trace combinations  
* Real‑time status output and **sortable results table** exportable to CSV

---

## 📂 Repository layout
```

modules/
├─ 1_STOMPscan.py          # ← this file (rename as you wish)
├─ stomp-defaults.txt     # username\:password pairs, one per line
└─ …                      # any other Ningu modules

````

---

## 🚀 Setup

1. **Clone / copy** the two files above into the `modules/` directory of your **Ningu** project.  
2. Verify Python 3.8+ and **PySide6** (≥ 6.4) are installed:
```
   bash
   pip install PySide6
````

3. Launch your main Ningu GUI (e.g. `python ningu-v1.0.0.py` or `python HACKtiveMQ-v1.0.0.py`).
   Ningu/HACKtiveMQ auto‑discovers the module and adds a **“STOMPscan v1.3.2”** tab.

---

## 🖥️ Using STOMPscan

| Step  | Action                                                                                                                                 |
| ----- | -------------------------------------------------------------------------------------------------------------------------------------- |
| **1** | Paste or load a list of hosts/IPs into **Hosts** box. Use **Load**, **Save**, **Clear**, or **Sort+Dedup** to manage the list.         |
| **2** | Pick the **port** (default **61613**) and toggle **TCP / SSL**.                                                                        |
| **3** | Click **Scan** or press **Enter** in the port box.                                                                                     |
| **4** | Watch the **Status** pane for live logging; results populate in the table.                                                             |
| **5** | Save results with **Output → Save** (CSV).                                                                                             |

**Column meanings**

| Column        | Description                                                   |        |
| ------------- | ------------------------------------------------------------- | ------ |
| Timestamp     | Local scan time (YYYY‑MM‑DD HH\:MM\:SS)                       |        |
| Hostname      | Target host                                                   |        |
| Port          | `<port>/<tcp or ssl>`                                         |        |
| Defaults      | `username:password` pairs that succeeded, `None`, or `error`  |        |
| Auth Status   | `disabled` / `enabled` / `unknown`                            |        |
| Server String | Broker banner (if provided)                                   |        |
| Fingerprint   | ‑ Known version (*e.g.* `v5.15.0-5.15.4`) or raw SHA‑256 hash |        |

---

## ⚙️ Configuration

* **Default credential list** → edit `modules/stomp-defaults.txt`
  Format: `username:password` (one per line).
  Lines starting with `#` are ignored.
* **Stack‑trace ↔ version mapping** lives in `STACK_TRACE_TO_VERSION` inside the module.
  Add new hashes as you discover them.

---

## 🛠️ Extending

STOMPscan follows Ningu’s plugin contract:

```python
class TabContent(QWidget):
    # exported QWidget inserted directly as a tab
```

Feel free to subclass, add new STOMP probes, or integrate other broker checks. Pull requests welcome!

---

## ❗ Disclaimer

This tool is intended for **authorized security testing and administrative auditing** only.
Unauthorized scanning may violate law or service terms; **use responsibly**.

---

# LoadActiveMQ Module

The `LoadActiveMQ` module is a component of the **HACKtiveMQ Suite**, designed to load and run specific versions of Apache ActiveMQ from `.zip` archives on a Windows system. It provides a graphical interface to select and execute ActiveMQ instances for testing or interaction.

**Important Notes**:
- This module is currently **Windows-only** due to its reliance on Windows-specific commands (`activemq.bat`, `taskkill`) and file paths.
- **Classic versions** of Apache ActiveMQ `.zip` files (e.g., `apache-activemq-5.9.1-bin.zip`) must be placed in the `modules/Load_ActiveMQ` directory.

## Overview

The `LoadActiveMQ` module allows users to:
- List available ActiveMQ versions from `.zip` files in the `modules/Load_ActiveMQ` directory.
- Extract and run a selected ActiveMQ version using `activemq.bat`.
- Automatically stop and clean up previous instances when switching versions.
- Log all actions (extraction, execution, errors) in a status window.

The module automatically creates the `modules/Load_ActiveMQ` directory if it does not exist, ensuring a seamless setup process.

## Requirements

### Software
- **Python**: Version 3.8 or later recommended.
- **Java Development Kit (JDK)**: Required to run ActiveMQ instances. The module references JDK 24 (e.g., `C:\Program Files\Java\jdk-24`), but other versions may work. Install Oracle JDK or OpenJDK and ensure `JAVA_HOME` is set or the path is correctly configured.
- **Windows Operating System**: The module is Windows-only.

### Python Dependencies
The following Python packages are required:
PySide6>=6.0.0
packaging>=21.0

## Installation

1. **Obtain the Module**:
   - The `LoadActiveMQ` module is part of the HACKtiveMQ Suite. Clone or download the suite repository, or extract the `load_activemq.py` file and its dependencies.

2. **Install Python Dependencies**:
   - Create a virtual environment (optional but recommended):
     ```bash
     python -m venv venv
     .\venv\Scripts\activate
     ```
   - Install the required packages:
     ```bash
     pip install -r requirements.txt
     ```
   - Alternatively, install directly:
     ```bash
     pip install PySide6>=6.0.0 packaging>=21.0
     ```

3. **Install Java Development Kit (JDK)**:
   - Download and install a JDK (e.g., [Oracle JDK](https://www.oracle.com/java/technologies/javase-downloads.html) or [OpenJDK](https://adoptium.net/)).
   - Set the `JAVA_HOME` environment variable to the JDK installation path (e.g., `C:\Program Files\Java\jdk-24`), or the module will attempt to set it automatically.

4. **Prepare ActiveMQ `.zip` Files**:
   - Download **classic versions** of Apache ActiveMQ `.zip` archives from the [Apache ActiveMQ website](https://activemq.apache.org/components/classic/download/) or other trusted sources.
   - Place the `.zip` files (e.g., `apache-activemq-5.9.1-bin.zip`) in the `modules/Load_ActiveMQ` directory. The module will create this directory automatically if it does not exist.

## Usage

1. **Launch the Module**:
   - Run the `LoadActiveMQ` module via the ningu framework or the HACKtiveMQ Suite.

2. **Select and Run ActiveMQ**:
   - The `ActiveMQ Versions` list displays available versions based on `.zip` files in `modules/Load_ActiveMQ`.
   - Click a version to:
     - Stop any running ActiveMQ instance (terminates `java.exe` processes).
     - Extract the selected `.zip` to a temporary directory (`modules/Load_ActiveMQ/temp`).
     - Run `activemq.bat` with the appropriate command (`start` for versions >= 5.10.0, otherwise no arguments).
   - Logs are displayed in the `Status` text box, including:
     - Directory creation (if applicable).
     - Extraction progress.
     - Command execution details.
     - Any errors (e.g., missing `activemq.bat`, JDK issues).

3. **Cleanup**:
   - Selecting a new version automatically stops the current instance and deletes the temporary directory.
   - The module ensures resources are released when closed, terminating any running ActiveMQ processes.

## Directory Structure
```
HACKtiveMQ_Suite/
├── modules/
│   ├── Load_ActiveMQ/              # Place ActiveMQ .zip files here
│   │   ├── apache-activemq-5.9.1-bin.zip
│   │   ├── apache-activemq-5.10.0-bin.zip
│   │   └── ...
└── 2_LoadActiveMQ.py               # LoadActiveMQ module
```

## Limitations
- **Windows-Only**: The module uses Windows-specific commands (`activemq.bat`, `taskkill`) and paths, making it incompatible with Linux or macOS without modifications.
- **ActiveMQ Classic**: Only classic versions of ActiveMQ are supported. Artemis or other variants may not work.
- **JDK Dependency**: A compatible JDK must be installed and configured.
- **Version Parsing**: The module assumes `.zip` filenames follow the format `apache-activemq-X.Y.Z-bin.zip`. Non-standard names may sort alphabetically instead of numerically.

## Troubleshooting
- **No Versions Listed**:
  - Ensure `.zip` files are in `modules/Load_ActiveMQ`.
  - Verify the files are valid ActiveMQ classic `.zip` archives.
- **JDK Errors**:
  - Check that `JAVA_HOME` is set or the JDK path in the code (`C:\Program Files\Java\jdk-24`) is correct.
  - Install a compatible JDK if missing.
- **Permission Issues**:
  - Run the application with administrator privileges if directory creation or process termination fails.
- **Logs**:
  - Check the `Status` text box for detailed error messages (e.g., extraction failures, command errors).

---

# Parley Module

The `Parley` module is a component of the **HACKtiveMQ Suite** and **ningu framework**, designed to act as a TCP/SSL proxy for intercepting and manipulating network traffic. It provides a graphical interface to configure proxy settings, load client and server certificates, and apply pluggable modules for processing network data.

## Overview

The `Parley` module enables users to:
- Set up a proxy server to relay traffic between a local endpoint (client-facing) and a remote endpoint (server-facing).
- Toggle TCP or SSL for both local and remote connections, with support for loading server and client certificates.
- Load and toggle pluggable client and server modules to process network traffic (e.g., display data in HEX, UTF-8, or modify HTTP headers).
- Log all proxy activity, including connection details and module outputs, to a status window and connection-specific log files in `modules/Parley_logs/<date>/`.
- Manage modules by enabling or disabling them via a GUI, moving module files between `enabled` and `disabled` directories.

The module dynamically loads Python modules from `modules/Parley_modules_client/enabled` and `modules/Parley_modules_server/enabled`, which are created automatically if they do not exist.

## Requirements

### Software
- **Python**: Version 3.8 or later recommended.
- **Operating System**: Compatible with Windows, Linux, and macOS.

### Python Dependencies
The following Python packages are required, as specified in `requirements.txt`:
PySide6>=6.0.0

## Installation

1. **Obtain the Module**:
   - The `Parley` module is part of the HACKtiveMQ Suite. Clone or download the suite repository, or extract the `3_Parley.py` file and its dependencies.

2. **Install Python Dependencies**:
   - Create a virtual environment (optional but recommended):
     ```bash
     python -m venv venv
     source venv/bin/activate  # On Linux/macOS
     venv\Scripts\activate     # On Windows
     ```
   - Install the required packages:
     ```bash
     pip install -r requirements.txt
     ```
   - Alternatively, install directly:
     ```bash
     pip install PySide6>=6.0.0
     ```

3. **Set Up Module Directories**:
   - Ensure the following directories exist (created automatically if missing):
     - `modules/Parley_modules_client/enabled`: For enabled client modules.
     - `modules/Parley_modules_client/disabled`: For disabled client modules.
     - `modules/Parley_modules_server/enabled`: For enabled server modules.
     - `modules/Parley_modules_server/disabled`: For disabled server modules.
     - `modules/Parley_module_libs`: For shared library modules (e.g., `lib3270.py`, `lib8583.py`).
   - Place client and server module files (e.g., `Display_Client_HEX.py`, `Display_Server_Python.py`) in the appropriate `enabled` or `disabled` directories.
   - Place shared library modules in `modules/Parley_module_libs`.

4. **Prepare Certificates** (if using SSL):
   - Obtain server and client certificates (`.pem` or `.crt` files) if enabling SSL for local or remote connections.
   - Certificates can be loaded via the GUI during configuration.

## Usage

1. **Launch the Module**:
   - Run the `Parley` module via the HACKtiveMQ Suite or the ningu framework.

2. **Configure Proxy Settings**:
   - **Local IP/Port**: Enter the IP address (e.g., `127.0.0.1`) and port (e.g., `8080`) for the proxy to listen on.
   - **Remote IP/Port**: Enter the target server’s IP address and port (e.g., `80` for HTTP).
   - **Local TLS**: Toggle the `Local TLS` button to enable SSL (`SSL`) or use TCP (`TCP`) for client connections. Load a server certificate if using SSL.
   - **Remote TLS**: Toggle the `Remote TLS` button to enable SSL (`SSL`) or use TCP (`TCP`) for server connections. Load a client certificate if using SSL.
   - **Certificates**:
     - Click `Load Server Cert` to select a server certificate (`.pem` or `.crt`) for local SSL.
     - Click `Load Client Cert` to select a client certificate for remote SSL.
     - Click `Clear` to remove certificate paths.

3. **Manage Modules**:
   - **Client Modules**: View available client modules in the `Client Modules` list. Click a module to toggle it between `enabled` and `disabled`, moving its `.py` file between `modules/Parley_modules_client/enabled` and `modules/Parley_modules_client/disabled`.
   - **Server Modules**: View available server modules in the `Server Modules` list. Click a module to toggle its status, moving its `.py` file between `modules/Parley_modules_server/enabled` and `modules/Parley_modules_server/disabled`.
   - Enabled modules are bolded in the lists and loaded automatically when starting the proxy.

4. **Start/Stop Proxy**:
   - Click the `Start` button to launch the proxy, which listens on the specified local IP/port and forwards traffic to the remote IP/port.
   - The `Status` text box logs events (e.g., `Started proxy: 127.0.0.1:8080 -> example.com:80`, `New server socket thread started for 127.0.0.1:12345`).
   - Connection-specific logs are saved to `modules/Parley_logs/<date>/<src_ip>-<src_port>-<dst_ip>-<dst_port>.log`.
   - Click `Stop` to halt the proxy and clean up resources.

5. **Monitor and Debug**:
   - The `Status` text box displays real-time logs, including module loading, connection details, and errors.
   - Check log files in `modules/Parley_logs/<date>/` for detailed connection-specific logs.

## Directory Structure
```
HACKtiveMQ_Suite/
├── modules/
│   ├── Parley_module_libs/         # Shared library modules
│   │   ├── lib3270.py
│   │   ├── lib8583.py
│   │   ├── log_utils.py
│   │   ├── solace_auth.py
│   │   └── ...
│   ├── Parley_modules_client/      # Client modules
│   │   ├── enabled/
│   │   │   ├── Display_Client_Python.py
│   │   │   └── ...
│   │   ├── disabled/
│   │   │   ├── Display_Client_HEX.py
│   │   │   ├── Display_Client_UTF8.py
│   │   │   └── ...
│   ├── Parley_modules_server/      # Server modules
│   │   ├── enabled/
│   │   │   ├── Display_Server_Python.py
│   │   │   └── ...
│   │   ├── disabled/
│   │   │   ├── Display_Server_HEX.py
│   │   │   ├── Display_Server_UTF8.py
│   │   │   └── ...
│   ├── Parley_logs/                # Log files (created automatically)
│   │   ├── <MM-DD-YYYY>/
│   │   │   ├── <src_ip>-<src_port>-<dst_ip>-<dst_port>.log
│   │   │   └── ...
└── 3_Parley.py                    # Parley module
```

## Limitations
- **Module Compatibility**: Modules must have a `module_function` that processes data and a `module_description` attribute, as expected by the `Parley` module.
- **SSL Certificates**: SSL connections require valid certificates. Missing or invalid certificates may cause connection failures.
- **Port Conflicts**: Ensure the local port is not in use by another application to avoid binding errors.
- **Thread Safety**: Modules must be thread-safe, as they are called in separate client threads.

## Troubleshooting
- **Proxy Fails to Start**:
  - Verify that the local and remote IP/port inputs are valid (e.g., numeric port, non-empty remote IP).
  - Check for port conflicts (`Error starting proxy: Address already in use`).
  - Ensure certificates are valid if using SSL (`Error in connection: [SSL: CERTIFICATE_VERIFY_FAILED]`).
- **Modules Not Loaded**:
  - Confirm that module files are in `modules/Parley_modules_client/enabled` or `modules/Parley_modules_server/enabled`.
  - Check the `Status` text box for errors (e.g., `Error loading module: ...`).
- **No Logs in Files**:
  - Ensure the `modules/Parley_logs/<date>/` directory is writable.
  - Check for errors in the `Status` text box (e.g., `Error writing to log file ...`).
- **Connection Issues**:
  - Verify remote server availability (`Error: Connection refused`).
  - Check TLS settings and certificate paths for SSL connections.

---

# SecretDecoderRing Module

The `SecretDecoderRing` module is a component of the **HACKtiveMQ Suite**, designed to decrypt ciphertexts using various encryption algorithms and modes on a Windows system. It provides a graphical interface to input ciphertexts, keys, and IVs/nonces, and attempts decryption using multiple cryptographic modules.

## Overview

The `SecretDecoderRing` module enables users to:
- Input ciphertexts, keys, and IVs/nonces in Base64, HEX, or ASCII formats.
- Load ciphertexts from files, sort and deduplicate them, and save results to CSV files.
- Attempt decryption using multiple encryption modules (e.g., AES, 3DES, Blowfish, CAST5, ChaCha20) stored in `modules/SecretDecoderRing_modules`.
- Display decryption results in a table, showing ciphertext, plaintext, algorithm, mode, key, and IV/nonce for successful decryptions with typeable ASCII output.
- Log all actions (input processing, decryption attempts, errors) in a status window.

The module dynamically loads encryption modules from the `modules/SecretDecoderRing_modules` directory, which is created automatically if it does not exist.

## Requirements

### Software
- **Python**: Version 3.8 or later recommended.

### Python Dependencies
The following Python packages are required, as specified in `requirements.txt`:
PySide6>=6.0.0
pycryptodome>=3.10.0

## Installation

1. **Obtain the Module**:
   - The `SecretDecoderRing` module is part of the HACKtiveMQ Suite. Clone or download the suite repository, or extract the `4_SecretDecoderRing.py` file and its dependencies.

2. **Install Python Dependencies**:
   - Create a virtual environment (optional but recommended):
     ```bash
     python -m venv venv
     .\venv\Scripts\activate
     ```
   - Install the required packages:
     ```bash
     pip install -r requirements.txt
     ```
   - Alternatively, install directly:
     ```bash
     pip install PySide6>=6.0.0 pycryptodome>=3.10.0
     ```

3. **Set Up Encryption Modules**:
   - Place encryption module files (e.g., `AES_v1.1.py`, `3DES_v1.0.py`, `Blowfish_v1.0.py`, `CAST5_v1.0.py`, `ChaCha20_v1.0.py`) in the `modules/SecretDecoderRing_modules` directory.
   - The module will create this directory automatically if it does not exist.
   - Ensure each module has a `decrypt` function compatible with the interface defined in `AES_v1.1.py`.

## Usage

1. **Launch the Module**:
   - Run the `SecretDecoderRing` module via the ningu framework or the HACKtiveMQ Suite.

2. **Input Data**:
   - **Key**: Enter the encryption key in the `Key` field (Base64, HEX, or ASCII format).
   - **IV/Nonce**: Enter the initialization vector or nonce in the `IV/Nonce` field (optional; defaults to 16 null bytes if empty).
   - **Ciphertext**: Enter one or more ciphertexts in the `CipherText` text box, one per line, or load from a file using the `Load` button.
   - Select the input format (Base64, HEX, ASCII) for each field using the respective combo boxes.

3. **Manage Ciphertexts**:
   - **Load**: Load ciphertexts from a `.txt` file into the `CipherText` text box.
   - **Save**: Save the `CipherText` text box contents to a `.txt` file.
   - **Clear**: Clear the `CipherText` text box.
   - **Sort+Dedup**: Sort and deduplicate ciphertext lines in the `CipherText` text box.

4. **Decrypt**:
   - Click the `Decrypt` button or press `Enter` in the `Key` field to attempt decryption.
   - The module processes each ciphertext using all loaded encryption modules (e.g., AES with modes ECB, CBC, CFB, OFB, CTR, GCM, EAX).
   - Successful decryptions producing typeable ASCII (printable characters 32-126) are displayed in the `PlainText` table with columns: Ciphertext, Plaintext, Algorithm, Mode, Key, IV/Nonce.
   - Logs in the `Status` text box detail input processing, decryption attempts, and errors (e.g., `Decryption succeeded with AES_v1_1 in CBC mode`, `Error processing ciphertext: Invalid base64 input`).

5. **Manage Plaintext**:
   - **Save**: Save the `PlainText` table contents to a `.csv` file.
   - **Clear**: Clear the `PlainText` table.

## Directory Structure
```
HACKtiveMQ_Suite/
├── modules/
│   ├── SecretDecoderRing_modules/   # Place encryption modules here
│   │   ├── AES_v1.1.py
│   │   ├── 3DES_v1.0.py
│   │   ├── Blowfish_v1.0.py
│   │   ├── CAST5_v1.0.py
│   │   ├── ChaCha20_v1.0.py
│   │   └── ...
└── 4_SecretDecoderRing.py          # SecretDecoderRing module
```

## Limitations
- **Encryption Modules**: Requires properly formatted modules in `modules/SecretDecoderRing_modules` with a `decrypt` function. Missing or incompatible modules will prevent decryption.
- **ASCII Output**: Only decryptions producing typeable ASCII (printable characters 32-126) are displayed in the `PlainText` table.

## Troubleshooting
- **No Decryption Results**:
  - Ensure encryption modules are in `modules/SecretDecoderRing_modules` and have a valid `decrypt` function.
  - Verify that the key, IV/nonce, and ciphertext formats match the expected input (e.g., correct Base64 or HEX).
  - Check the `Status` text box for errors (e.g., `Error processing Key: Invalid hex characters`).
- **Modules Not Loaded**:
  - Confirm the `modules/SecretDecoderRing_modules` directory exists and contains `.py` files.
  - Check for error messages in the `Status` text box (e.g., `Error: Directory 'modules/SecretDecoderRing_modules' not found`).
- **Permission Issues**:
  - Run the application with administrator privileges if directory creation or file access fails.
- **Invalid Input**:
  - Ensure ciphertexts, keys, and IVs/nonces are valid for the selected format (Base64, HEX, ASCII).
  - Review the `Status` text box for specific error messages.

## Contributing
Contributions to the `SecretDecoderRing` module are welcome! To contribute:
1. Fork the HACKtiveMQ Suite repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

Please test changes on Windows and ensure compatibility with the module’s functionality and encryption modules.

## License
This module is licensed under the GNU General Public License v3.0. See the [LICENSE](https://www.gnu.org/licenses/) file for details.

## Contact
For issues, questions, or suggestions, contact Garland Glessner at gglesner@gmail.com.
