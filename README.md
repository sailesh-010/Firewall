# Firewall Manager

This script allows you to manage firewall rules on both Linux (using UFW) and Windows (using Windows Defender Firewall). You can create rule files to block or allow specific IP addresses, and then apply or revert those rules.

## Prerequisites

### Linux

This script requires `ufw` to be installed. You can install it on Debian-based systems with:

```bash
sudo apt-get update
sudo apt-get install ufw
```

### Windows

This script uses the built-in Windows Defender Firewall and does not require any additional software.

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/your-username/firewall-manager.git
    cd firewall-manager
    ```

2.  (Optional) Create a virtual environment:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

## Usage

1.  **Create a Rule File**:
    *   Run the script: `python3 main.py`
    *   Select option `1` to create a new rule file.
    *   You can choose between a `DENY_LIST` (block specific sites), `ALLOW_LIST` (allow specific sites), or `HYBRID` (specify for each).
    *   Enter the domain names you want to block or allow. The script will resolve them to IP addresses.
    *   Save the rule file with a `.json` extension.

2.  **Start the Firewall**:
    *   Run the script: `sudo python3 main.py` (on Linux) or run as Administrator on Windows.
    *   Select option `2` to start the firewall.
    *   Choose the rule file you want to apply.

3.  **Stop the Firewall**:
    *   Run the script with the same privileges.
    *   Select option `3` to stop the firewall and revert all changes.

## Disclaimer

This script modifies your system's firewall settings. Use it with caution and ensure you understand the rules you are applying. The developers are not responsible for any issues that may arise from the use of this script.
