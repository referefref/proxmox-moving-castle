#!/usr/bin/env python3

"""
Proxmox Moving Castle (PMC) Setup Script

This script performs the initial setup for the Proxmox Moving Castle system.
It creates the necessary configuration files, sets up the router VM,
and prepares the Proxmox environment for the PMC controller.

Usage: python pmc_setup.py [--help]
"""

import subprocess
import sys
import time
import yaml
from proxmoxer import ProxmoxAPI
import paramiko
import argparse
import logging

def setup_logging():
    """Set up logging for the setup script."""
    logger = logging.getLogger('PMCSetup')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)
    return logger

logger = setup_logging()

def run_command(command):
    """
    Execute a shell command and handle its output.

    Args:
        command (str): The command to execute.

    Returns:
        str: The command output.

    Raises:
        SystemExit: If the command execution fails.
    """
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, error = process.communicate()
        if process.returncode != 0:
            logger.error(f"Error executing command: {command}")
            logger.error(f"Error message: {error.decode('utf-8')}")
            sys.exit(1)
        return output.decode('utf-8')
    except Exception as e:
        logger.error(f"An error occurred while executing the command: {e}")
        sys.exit(1)

def create_config_file():
    """
    Create the PMC configuration file by prompting the user for necessary information.

    Returns:
        dict: The created configuration.
    """
    try:
        config = {
            'proxmox': {
                'host': input("Enter Proxmox host IP: "),
                'user': input("Enter Proxmox username (e.g., root@pam): "),
                'password': input("Enter Proxmox password: "),
                'node': input("Enter Proxmox node name (default is 'pve'): ") or 'pve',
                'storage': input("Enter storage name (default is 'local'): ") or 'local'
            },
            'router': {
                'ip': input("Enter desired router IP (e.g., 192.168.1.1): "),
                'user': 'root',
                'password': input("Enter desired router root password: ")
            },
            'production_port_range': {
                'start': int(input("Enter start of production port range: ")),
                'end': int(input("Enter end of production port range: "))
            },
            'decoy_port_range': {
                'start': int(input("Enter start of decoy port range: ")),
                'end': int(input("Enter end of decoy port range: "))
            },
            'rotation_interval': int(input("Enter rotation interval in seconds: ")),
            'recycle_interval': int(input("Enter recycle interval in seconds: "))
        }

        with open('pmc_config.yaml', 'w') as f:
            yaml.dump(config, f)

        logger.info("Configuration file 'pmc_config.yaml' has been created.")
        return config
    except Exception as e:
        logger.error(f"An error occurred while creating the configuration file: {e}")
        sys.exit(1)

def setup_proxmox_api(config):
    """
    Set up a connection to the Proxmox API.

    Args:
        config (dict): The PMC configuration.

    Returns:
        ProxmoxAPI: The Proxmox API connection object.
    """
    try:
        proxmox = ProxmoxAPI(config['proxmox']['host'],
                             user=config['proxmox']['user'],
                             password=config['proxmox']['password'],
                             verify_ssl=False)
        return proxmox
    except Exception as e:
        logger.error(f"Failed to connect to Proxmox API: {e}")
        sys.exit(1)

def download_debian_iso(proxmox, config):
    """
    Download the Debian ISO to the Proxmox server.

    Args:
        proxmox (ProxmoxAPI): The Proxmox API connection object.
        config (dict): The PMC configuration.
    """
    try:
        node = proxmox.nodes(config['proxmox']['node'])
        debian_url = "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-11.3.0-amd64-netinst.iso"
        node.storage(config['proxmox']['storage']).download_url.create(content='iso', filename='debian-11.3.0-amd64-netinst.iso', url=debian_url)
        logger.info("Debian ISO downloaded successfully.")
    except Exception as e:
        logger.error(f"Failed to download Debian ISO: {e}")
        sys.exit(1)

def create_router_vm(proxmox, config):
    """
    Create the router VM in Proxmox.

    Args:
        proxmox (ProxmoxAPI): The Proxmox API connection object.
        config (dict): The PMC configuration.

    Returns:
        int: The VMID of the created router VM.
    """
    try:
        node = proxmox.nodes(config['proxmox']['node'])
        vmid = int(node.nextid.get())
        node.qemu.create(
            vmid=vmid,
            name='router',
            memory=1024,
            cores=2,
            net0='model=virtio,bridge=vmbr0',
            net1='model=virtio,bridge=vmbr1',
            ide2=f"{config['proxmox']['storage']}:iso/debian-11.3.0-amd64-netinst.iso,media=cdrom"
        )
        logger.info(f"Router VM created with ID: {vmid}")
        return vmid
    except Exception as e:
        logger.error(f"Failed to create router VM: {e}")
        sys.exit(1)

def start_vm(proxmox, config, vmid):
    """
    Start a VM in Proxmox.

    Args:
        proxmox (ProxmoxAPI): The Proxmox API connection object.
        config (dict): The PMC configuration.
        vmid (int): The VMID of the VM to start.
    """
    try:
        proxmox.nodes(config['proxmox']['node']).qemu(vmid).status.start.post()
        logger.info(f"Started VM with ID: {vmid}")
    except Exception as e:
        logger.error(f"Failed to start VM {vmid}: {e}")
        sys.exit(1)

def wait_for_vm_boot(proxmox, config, vmid):
    """
    Wait for a VM to boot up.

    Args:
        proxmox (ProxmoxAPI): The Proxmox API connection object.
        config (dict): The PMC configuration.
        vmid (int): The VMID of the VM to wait for.

    Returns:
        bool: True if the VM booted successfully, False otherwise.
    """
    logger.info("Waiting for VM to boot...")
    for _ in range(60):  # Wait up to 5 minutes
        try:
            status = proxmox.nodes(config['proxmox']['node']).qemu(vmid).status.current.get()
            if status['status'] == 'running':
                time.sleep(60)  # Give it an extra minute to fully boot
                return True
        except Exception as e:
            logger.error(f"Error checking VM status: {e}")
        time.sleep(5)
    logger.error("VM did not boot in time.")
    return False

def setup_router(proxmox, config, vmid):
    """
    Set up the router VM with necessary configurations.

    Args:
        proxmox (ProxmoxAPI): The Proxmox API connection object.
        config (dict): The PMC configuration.
        vmid (int): The VMID of the router VM.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    logger.info("Attempting to connect to the router VM...")
    for _ in range(12):  # Try for 2 minutes
        try:
            ssh.connect(config['router']['ip'], username=config['router']['user'], password=config['router']['password'])
            logger.info("Successfully connected to the router VM.")
            break
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            time.sleep(10)
    else:
        logger.error("Failed to connect to the router VM after multiple attempts.")
        return

    commands = [
        "apt update && apt upgrade -y",
        "apt install -y iptables-persistent",
        f"echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf",
        "sysctl -p",
        "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
        "iptables-save > /etc/iptables/rules.v4"
    ]

    for command in commands:
        logger.info(f"Executing: {command}")
        try:
            stdin, stdout, stderr = ssh.exec_command(command)
            logger.info(stdout.read().decode('utf-8'))
            logger.error(stderr.read().decode('utf-8'))
        except Exception as e:
            logger.error(f"Error executing command on router VM: {e}")

    ssh.close()
    logger.info("Router setup completed.")

def main():
    """
    Main function to run the PMC setup process.
    """
    parser = argparse.ArgumentParser(description="Proxmox Moving Castle (PMC) Setup")
    parser.add_argument("--non-interactive", action="store_true", help="Run setup without user prompts (requires pre-configured pmc_config.yaml)")
    args = parser.parse_args()

    logger.info("Starting ProxmoxMovingCastle setup...")

    if args.non_interactive:
        try:
            with open('pmc_config.yaml', 'r') as f:
                config = yaml.safe_load(f)
        except FileNotFoundError:
            logger.error("pmc_config.yaml not found. Required for non-interactive mode.")
            sys.exit(1)
    else:
        config = create_config_file()

    proxmox = setup_proxmox_api(config)

    logger.info("Downloading Debian ISO...")
    download_debian_iso(proxmox, config)

    logger.info("Creating router VM...")
    router_vmid = create_router_vm(proxmox, config)

    logger.info("Starting router VM...")
    start_vm(proxmox, config, router_vmid)

    if wait_for_vm_boot(proxmox, config, router_vmid):
        logger.info("Setting up router...")
        setup_router(proxmox, config, router_vmid)
    else:
        logger.error("Router VM did not boot successfully. Please check the VM status in Proxmox.")

    # Update config with router VMID
    config['router_vm_id'] = router_vmid
    with open('pmc_config.yaml', 'w') as f:
        yaml.dump(config, f)

    logger.info("\nInitial setup completed. Please review the 'pmc_config.yaml' file and adjust as needed.")
    logger.info("You can now run the main ProxmoxMovingCastle script to start the system.")

if __name__ == "__main__":
    main()
