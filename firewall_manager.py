
import subprocess
import json
import os
import platform

class FirewallManager:
    def __new__(cls, rules_file):
        os_type = platform.system()
        if os_type == "Linux":
            return UFWManager(rules_file)
        elif os_type == "Windows":
            return WindowsFirewallManager(rules_file)
        else:
            raise NotImplementedError(f"Unsupported OS: {os_type}")

class BaseFirewallManager:
    def __init__(self, rules_file):
        """Initializes the FirewallManager by loading rules from a JSON file."""
        self.rules_file = rules_file
        self.rules_config = self.load_rules(rules_file)
        self.applied_rules = []

    def load_rules(self, rules_file):
        """Reads rules from the specified JSON file."""
        try:
            with open(rules_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: The rules file '{rules_file}' was not found.")
            return {}

    def apply_rules(self):
        raise NotImplementedError

    def revert_rules(self):
        raise NotImplementedError

class UFWManager(BaseFirewallManager):
    def _execute_ufw_command(self, command, silent=False, ufw_input=None):
        """
        Executes a ufw command and handles potential errors.
        Requires administrator/root privileges to run.
        """
        try:
            result = subprocess.run(command, check=True, text=True, capture_output=True, input=ufw_input)
            if not silent:
                print(result.stdout.strip())
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error executing command: '{' '.join(e.cmd)}'")
            print(f"Return Code: {e.returncode}")
            print(f"Error: {e.stderr.strip()}")
            print("\nNOTE: This program requires administrator/root privileges to modify ufw rules.")
            return False
        except FileNotFoundError:
            print("Error: 'ufw' command not found. Please ensure it is installed.")
            return False

    def apply_rules(self):
        """Applies firewall rules to the system using ufw."""
        if not self.rules_config:
            print("No rules to apply. Exiting.")
            return

        rule_type = self.rules_config.get("rule_type", "HYBRID")
        rules = self.rules_config.get("rules", self.rules_config)
        
        print("\nAttempting to apply rules. This requires administrator/root privileges.")
        print("Please run this program with 'sudo python3 main.py' if you have not already.")
        
        # Enable UFW first
        print("\nEnabling UFW...")
        enable_command = ["sudo", "ufw", "enable"]
        if self._execute_ufw_command(enable_command, ufw_input="y\n"):
            self.applied_rules.append(enable_command)
        else:
            print("Failed to enable UFW. Aborting rule application.")
            return
        
        print("\nApplying rules...")

        if rule_type == "DENY_LIST":
            for rule in rules:
                ip_address = rule.get("ip_address")
                if ip_address:
                    command = ["sudo", "ufw", "deny", "out", "to", ip_address]
                    if self._execute_ufw_command(command, silent=True):
                        self.applied_rules.append(command)
                        print(f"Applied: DENY outgoing to {ip_address} ({rule.get('hostname', 'Unknown Host')})")
        
        elif rule_type == "ALLOW_LIST":
            print("Setting default policy to DENY outgoing connections...")
            self._execute_ufw_command(["sudo", "ufw", "default", "deny", "outgoing"])
            self.applied_rules.append(["sudo", "ufw", "default", "deny", "outgoing"])
            
            for rule in rules:
                ip_address = rule.get("ip_address")
                if ip_address:
                    command = ["sudo", "ufw", "allow", "out", "to", ip_address]
                    if self._execute_ufw_command(command, silent=True):
                        self.applied_rules.append(command)
                        print(f"Applied: ALLOW outgoing to {ip_address} ({rule.get('hostname', 'Unknown Host')})")
        
        elif rule_type == "HYBRID":
            for rule in rules:
                ip_address = rule.get("ip_address")
                action = rule.get("action")
                if ip_address and action:
                    ufw_action = "allow" if action == "ALLOW" else "deny"
                    command = ["sudo", "ufw", ufw_action, "out", "to", ip_address]
                    if self._execute_ufw_command(command, silent=True):
                        self.applied_rules.append(command)
                        print(f"Applied: {action} outgoing to {ip_address} ({rule.get('hostname', 'Unknown Host')})")
        
        print("\nFirewall rules have been applied successfully.")
        
    def revert_rules(self):
        """Reverts the applied rules to restore the previous state."""
        if not self.applied_rules:
            print("No rules to revert. Firewall is not active or no rules were applied by this program.")
            return
            
        print("\nReverting firewall rules...")
        
        for command in reversed(self.applied_rules):
            if len(command) > 2 and command[2] == "default":
                print("Note: Default policy changes are not reverted automatically.")
                print("If you changed the default policy, you may need to revert it manually.")
                continue

            if len(command) > 2 and command[2] == "enable":
                disable_cmd = ["sudo", "ufw", "disable"]
                self._execute_ufw_command(disable_cmd, silent=True)
                continue

            if len(command) > 2:
                delete_cmd = command.copy()
                delete_cmd.insert(2, "delete")
                self._execute_ufw_command(delete_cmd, silent=True)
            
        print("Firewall rules reverted successfully.")
        self.applied_rules = []

class WindowsFirewallManager(BaseFirewallManager):
    def _execute_netsh_command(self, command, silent=False):
        """
        Executes a netsh command and handles potential errors.
        Requires administrator/root privileges to run.
        """
        try:
            result = subprocess.run(command, check=True, text=True, capture_output=True, shell=True)
            if not silent:
                print(result.stdout.strip())
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error executing command: '{e.cmd}'")
            print(f"Return Code: {e.returncode}")
            print(f"Error: {e.stderr.strip()}")
            print("\nNOTE: This program requires administrator privileges to modify firewall rules.")
            return False
        except FileNotFoundError:
            print("Error: 'netsh' command not found. This program is intended to run on Windows.")
            return False

    def apply_rules(self):
        """Applies firewall rules to the system using netsh."""
        if not self.rules_config:
            print("No rules to apply. Exiting.")
            return

        rule_type = self.rules_config.get("rule_type", "HYBRID")
        rules = self.rules_config.get("rules", self.rules_config)
        
        print("\nAttempting to apply rules. This requires administrator privileges.")

        if rule_type == "DENY_LIST":
            for i, rule in enumerate(rules):
                ip_address = rule.get("ip_address")
                hostname = rule.get("hostname", f"Rule_{i}")
                if ip_address:
                    rule_name = f"Block_{hostname}"
                    command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={ip_address}'
                    if self._execute_netsh_command(command, silent=True):
                        self.applied_rules.append(rule_name)
                        print(f"Applied: DENY outgoing to {ip_address} ({hostname})")
        
        elif rule_type == "ALLOW_LIST":
            print("Setting default policy to BLOCK outgoing connections...")
            command_block = 'netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound'
            self._execute_netsh_command(command_block)
            self.applied_rules.append("ALLOW_LIST_DEFAULT_BLOCK")

            for i, rule in enumerate(rules):
                ip_address = rule.get("ip_address")
                hostname = rule.get("hostname", f"Rule_{i}")
                if ip_address:
                    rule_name = f"Allow_{hostname}"
                    command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=allow remoteip={ip_address}'
                    if self._execute_netsh_command(command, silent=True):
                        self.applied_rules.append(rule_name)
                        print(f"Applied: ALLOW outgoing to {ip_address} ({hostname})")
        
        elif rule_type == "HYBRID":
            for i, rule in enumerate(rules):
                ip_address = rule.get("ip_address")
                action = rule.get("action")
                hostname = rule.get("hostname", f"Rule_{i}")
                if ip_address and action:
                    rule_name = f"{action}_{hostname}"
                    netsh_action = "block" if action == "DENY" else "allow"
                    command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action={netsh_action} remoteip={ip_address}'
                    if self._execute_netsh_command(command, silent=True):
                        self.applied_rules.append(rule_name)
                        print(f"Applied: {action} outgoing to {ip_address} ({hostname})")
        
        print("\nFirewall rules have been applied successfully.")

    def revert_rules(self):
        """Reverts the applied rules to restore the previous state."""
        if not self.applied_rules:
            print("No rules to revert. Firewall is not active or no rules were applied by this program.")
            return
            
        print("\nReverting firewall rules...")
        
        for rule_name in reversed(self.applied_rules):
            if rule_name == "ALLOW_LIST_DEFAULT_BLOCK":
                print("Restoring default outgoing policy to ALLOW...")
                command_allow = 'netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound'
                self._execute_netsh_command(command_allow, silent=True)
                continue

            command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            self._execute_netsh_command(command, silent=True)
            
        print("Firewall rules reverted successfully.")
        self.applied_rules = []