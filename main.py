import json
import socket
import os
from firewall_manager import FirewallManager

# Global variable to hold the active UFWManager instance
active_firewall_manager = None

def create_blocking_rule_file():
    """
    Guides the user through creating a new rule file with DENY_LIST, ALLOW_LIST, or HYBRID rules.
    """
    print("\n--- Create New Blocking Rule File ---")
    print("Select a rule type:")
    print("1. DENY_LIST (Block specific sites, allow all others)")
    print("2. ALLOW_LIST (Allow specific sites, block all others)")
    print("3. HYBRID (Specify ALLOW or DENY for each site)")
    
    rule_type_choice = input("Enter your choice (1, 2, or 3): ")
    
    blocked_rules = []
    
    if rule_type_choice == '1':
        print("\n--- Creating a DENY_LIST rule file ---")
        rule_type = "DENY_LIST"
        print("Enter domain names to block (type '99' to finish):")
        
        while True:
            domain_name = input("Domain: ")
            if domain_name == '99':
                break
            try:
                ip_address = socket.gethostbyname(domain_name)
                blocked_rules.append({"ip_address": ip_address, "hostname": domain_name})
            except socket.gaierror:
                print(f"Error: Could not resolve '{domain_name}'. Please try again.")

    elif rule_type_choice == '2':
        print("\n--- Creating an ALLOW_LIST rule file ---")
        rule_type = "ALLOW_LIST"
        print("Enter domain names to allow (type '99' to finish):")
        
        while True:
            domain_name = input("Domain: ")
            if domain_name == '99':
                break
            try:
                ip_address = socket.gethostbyname(domain_name)
                blocked_rules.append({"ip_address": ip_address, "hostname": domain_name})
            except socket.gaierror:
                print(f"Error: Could not resolve '{domain_name}'. Please try again.")

    elif rule_type_choice == '3':
        print("\n--- Creating a HYBRID rule file ---")
        rule_type = "HYBRID"
        print("Enter domains and specify action (type '99' to finish):")
        
        while True:
            domain_name = input("Domain: ")
            if domain_name == '99':
                break
            
            action_choice = input("Action for this domain (ALLOW or DENY): ").upper()
            if action_choice not in ["ALLOW", "DENY"]:
                print("Invalid action. Please enter 'ALLOW' or 'DENY'.")
                continue
            
            try:
                ip_address = socket.gethostbyname(domain_name)
                blocked_rules.append({"ip_address": ip_address, "hostname": domain_name, "action": action_choice})
            except socket.gaierror:
                print(f"Error: Could not resolve '{domain_name}'. Please try again.")
    
    else:
        print("Invalid choice. Returning to main menu.")
        return

    print("\n--- Rules to be saved ---")
    if not blocked_rules:
        print("No rules were added.")
    else:
        for rule in blocked_rules:
            if rule_type == "HYBRID":
                print(f"-> {rule['action']}: {rule['hostname']} ({rule['ip_address']})")
            else:
                print(f"-> {rule_type}: {rule['hostname']} ({rule['ip_address']})")

    if blocked_rules:
        filename = input("\nEnter the name for the new rules file (e.g., 'blocked_sites.json'): ")
        
        # Automatically add the .json extension
        if not filename.endswith('.json'):
            filename += '.json'
        
        final_rules = {"rule_type": rule_type, "rules": blocked_rules} if rule_type != "HYBRID" else blocked_rules
        
        with open(filename, 'w') as f:
            json.dump(final_rules, f, indent=4)
            
        print(f"\nSuccessfully created and saved a new rule file named '{filename}'.")
    else:
        print("No file was created.")

def select_rule_file_and_start():
    """Finds all .json files and prompts the user to select one to start the firewall."""
    global active_firewall_manager

    print("\n--- Select a Rule File ---")
    files = [f for f in os.listdir('.') if f.endswith('.json')]
    if not files:
        print("No JSON rule files found in the current directory.")
        return

    for i, filename in enumerate(files):
        print(f"{i + 1}. {filename}")
    print("99. Back to Main Menu")

    while True:
        choice = input("Enter your choice: ")
        if choice == '99':
            print("Returning to the main menu.")
            return
        try:
            index = int(choice) - 1
            if 0 <= index < len(files):
                selected_file = files[index]
                print(f"Using rule file '{selected_file}'.")
                active_firewall_manager = FirewallManager(selected_file)
                active_firewall_manager.apply_rules()
                return
            else:
                print("Invalid choice. Please enter a number from the list.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def stop_firewall():
    """Stops the firewall by reverting all applied rules."""
    global active_firewall_manager

    if active_firewall_manager:
        active_firewall_manager.revert_rules()
        active_firewall_manager = None
    else:
        print("No firewall rules are currently active to revert.")

def main_menu():
    """Main menu of the firewall program."""
    while True:
        print("\n--- Main Menu ---")
        print("1. Create new blocking rule file")
        print("2. Start the firewall")
        print("3. Stop the firewall")
        print("4. Exit")

        opt = input("Enter your choice: ")
        
        if opt == "1":
            create_blocking_rule_file()
        
        elif opt == "2":
            select_rule_file_and_start()
            
        elif opt == "3":
            stop_firewall()
        
        elif opt == "4":
            print("Exiting program.")
            break
            
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu()