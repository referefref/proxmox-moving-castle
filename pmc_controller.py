#!/usr/bin/env python3

"""
Proxmox Moving Castle (PMC) Controller

This script implements a moving target defense system for Proxmox environments.
It manages the creation, rotation, and monitoring of both production and decoy services
using LXC containers and full VMs.

Usage: python pmc_controller.py [--help] [--pmc-config FILE] [--instances-config FILE]

For more information, use the --help option.
"""

import time
import random
import logging
import yaml
from proxmoxer import ProxmoxAPI
import paramiko
import sys
import ipaddress
import argparse
import re

class ProxmoxMovingCastle:
    def __init__(self, pmc_config_file, instances_config_file):
        """
        Initialize the ProxmoxMovingCastle controller.

        Args:
            pmc_config_file (str): Path to the PMC configuration file.
            instances_config_file (str): Path to the instances configuration file.
        """
        self.pmc_config = self.load_config(pmc_config_file)
        self.instances_config = self.load_config(instances_config_file)
        
        self.proxmox = self.connect_proxmox()
        self.router_vm_id = self.pmc_config['router_vm_id']
        self.production_services = self.instances_config['production_services']
        self.decoy_services = self.instances_config['decoy_services']
        
        self.logger = self.setup_logging()

    def load_config(self, config_file):
        """
        Load and parse a YAML configuration file.

        Args:
            config_file (str): Path to the configuration file.

        Returns:
            dict: Parsed configuration data.

        Raises:
            SystemExit: If the file is not found or cannot be parsed.
        """
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            self.logger.error(f"Configuration file '{config_file}' not found.")
            sys.exit(1)
        except yaml.YAMLError as e:
            self.logger.error(f"Error parsing configuration file: {e}")
            sys.exit(1)

    def connect_proxmox(self):
        """
        Establish a connection to the Proxmox API.

        Returns:
            ProxmoxAPI: Proxmox API connection object.

        Raises:
            SystemExit: If connection to Proxmox API fails.
        """
        try:
            return ProxmoxAPI(self.pmc_config['proxmox']['host'],
                              user=self.pmc_config['proxmox']['user'],
                              password=self.pmc_config['proxmox']['password'],
                              verify_ssl=False)
        except Exception as e:
            self.logger.error(f"Failed to connect to Proxmox API: {e}")
            sys.exit(1)

    def setup_logging(self):
        """
        Set up logging for the PMC controller.

        Returns:
            logging.Logger: Configured logger object.
        """
        logger = logging.getLogger('ProxmoxMovingCastle')
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler('pmc.log')
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(handler)
        return logger

    def create_lxc(self, name, template, cpu, memory):
        """
        Create a new LXC container in Proxmox.

        Args:
            name (str): Name of the container.
            template (str): Template to use for the container.
            cpu (int): Number of CPU cores.
            memory (int): Amount of memory in MB.

        Returns:
            int: VMID of the created container, or None if creation fails.
        """
        try:
            node = self.proxmox.nodes(self.pmc_config['proxmox']['node'])
            next_vmid = int(node.nextid.get())
            node.lxc.create(vmid=next_vmid,
                            ostemplate=template,
                            hostname=name,
                            cores=cpu,
                            memory=memory,
                            net0='name=eth0,bridge=vmbr0,ip=dhcp')
            return next_vmid
        except Exception as e:
            self.logger.error(f"Failed to create LXC container: {e}")
            return None

    def create_vm(self, name, template, cpu, memory):
        """
        Create a new VM in Proxmox.

        Args:
            name (str): Name of the VM.
            template (str): Template to use for the VM.
            cpu (int): Number of CPU cores.
            memory (int): Amount of memory in MB.

        Returns:
            int: VMID of the created VM, or None if creation fails.
        """
        try:
            node = self.proxmox.nodes(self.pmc_config['proxmox']['node'])
            next_vmid = int(node.nextid.get())
            node.qemu.create(vmid=next_vmid,
                             name=name,
                             ostype='l26',
                             ide2=f'{self.pmc_config["proxmox"]["storage"]}:iso/{template},media=cdrom',
                             sockets=1,
                             cores=cpu,
                             memory=memory,
                             net0='model=virtio,bridge=vmbr0')
            return next_vmid
        except Exception as e:
            self.logger.error(f"Failed to create VM: {e}")
            return None

    def start_container(self, vmid):
        """Start an LXC container."""
        try:
            self.proxmox.nodes(self.pmc_config['proxmox']['node']).lxc(vmid).status.start.post()
        except Exception as e:
            self.logger.error(f"Failed to start LXC container {vmid}: {e}")

    def start_vm(self, vmid):
        """Start a VM."""
        try:
            self.proxmox.nodes(self.pmc_config['proxmox']['node']).qemu(vmid).status.start.post()
        except Exception as e:
            self.logger.error(f"Failed to start VM {vmid}: {e}")

    def stop_container(self, vmid):
        """Stop an LXC container."""
        try:
            self.proxmox.nodes(self.pmc_config['proxmox']['node']).lxc(vmid).status.stop.post()
        except Exception as e:
            self.logger.error(f"Failed to stop LXC container {vmid}: {e}")

    def stop_vm(self, vmid):
        """Stop a VM."""
        try:
            self.proxmox.nodes(self.pmc_config['proxmox']['node']).qemu(vmid).status.stop.post()
        except Exception as e:
            self.logger.error(f"Failed to stop VM {vmid}: {e}")

    def delete_container(self, vmid):
        """Delete an LXC container."""
        try:
            self.proxmox.nodes(self.pmc_config['proxmox']['node']).lxc(vmid).delete()
        except Exception as e:
            self.logger.error(f"Failed to delete LXC container {vmid}: {e}")

    def delete_vm(self, vmid):
        """Delete a VM."""
        try:
            self.proxmox.nodes(self.pmc_config['proxmox']['node']).qemu(vmid).delete()
        except Exception as e:
            self.logger.error(f"Failed to delete VM {vmid}: {e}")

    def update_router_port_forward(self, external_port, internal_ip, internal_port):
        """
        Update port forwarding rules on the router VM.

        Args:
            external_port (int): External port to forward from.
            internal_ip (str): Internal IP to forward to.
            internal_port (int): Internal port to forward to.
        """
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.pmc_config['router']['ip'], 
                        username=self.pmc_config['router']['user'], 
                        password=self.pmc_config['router']['password'])
            
            cmd = f"iptables -t nat -A PREROUTING -p tcp --dport {external_port} -j DNAT --to-destination {internal_ip}:{internal_port}"
            ssh.exec_command(cmd)
            
            ssh.close()
        except Exception as e:
            self.logger.error(f"Failed to update router port forwarding: {e}")

    def get_container_ip(self, vmid):
        """Get the IP address of an LXC container."""
        try:
            config = self.proxmox.nodes(self.pmc_config['proxmox']['node']).lxc(vmid).config.get()
            return config['net0'].split(',')[2].split('=')[1]
        except Exception as e:
            self.logger.error(f"Failed to get IP for LXC container {vmid}: {e}")
            return None

    def get_vm_ip(self, vmid):
        """Get the IP address of a VM."""
        try:
            config = self.proxmox.nodes(self.pmc_config['proxmox']['node']).qemu(vmid).config.get()
            return config['net0'].split(',')[2].split('=')[1]
        except Exception as e:
            self.logger.error(f"Failed to get IP for VM {vmid}: {e}")
            return None

    def rotate_production_service(self, service):
        """
        Rotate a production service by creating a new instance and removing the old one.

        Args:
            service (dict): Service configuration dictionary.
        """
        self.stop_container(service['vmid']) if service['type'] == 'lxc' else self.stop_vm(service['vmid'])
        
        new_vmid = self.create_lxc(service['name'], service['template'], service['cpu'], service['memory']) if service['type'] == 'lxc' else self.create_vm(service['name'], service['template'], service['cpu'], service['memory'])
        
        if new_vmid is None:
            self.logger.error(f"Failed to create new instance for service {service['name']}")
            return

        self.start_container(new_vmid) if service['type'] == 'lxc' else self.start_vm(new_vmid)
        
        new_internal_ip = self.get_container_ip(new_vmid) if service['type'] == 'lxc' else self.get_vm_ip(new_vmid)
        if new_internal_ip:
            new_external_port = random.randint(self.pmc_config['production_port_range']['start'], 
                                               self.pmc_config['production_port_range']['end'])
            self.update_router_port_forward(new_external_port, new_internal_ip, service['internal_port'])
        else:
            self.logger.error(f"Failed to get new IP for service {service['name']}")
            return

        self.delete_container(service['vmid']) if service['type'] == 'lxc' else self.delete_vm(service['vmid'])
        
        service['vmid'] = new_vmid
        service['external_port'] = new_external_port
        self.logger.info(f"Rotated production service {service['name']} to new VMID {new_vmid} and port {new_external_port}")

    def recycle_decoy_service(self, decoy):
        """
        Recycle a decoy service by creating a new instance and removing the old one.

        Args:
            decoy (dict): Decoy service configuration dictionary.
        """
        self.delete_container(decoy['vmid']) if decoy['type'] == 'lxc' else self.delete_vm(decoy['vmid'])
        
        new_vmid = self.create_lxc(decoy['name'], decoy['template'], decoy['cpu'], decoy['memory']) if decoy['type'] == 'lxc' else self.create_vm(decoy['name'], decoy['template'], decoy['cpu'], decoy['memory'])
        
        if new_vmid is None:
            self.logger.error(f"Failed to create new instance for decoy {decoy['name']}")
            return

        self.start_container(new_vmid) if decoy['type'] == 'lxc' else self.start_vm(new_vmid)
        
        decoy['vmid'] = new_vmid
        decoy['last_check'] = time.time()
        self.logger.info(f"Recycled decoy service {decoy['name']} to new VMID {new_vmid}")

    def monitor_decoy_logs(self, decoy):
        """
        Monitor the logs of a decoy service for suspicious activity.

        Args:
            decoy (dict): Decoy service configuration dictionary.
        """
        try:
            log_file = decoy['log_monitoring']['log_file']
            success_pattern = decoy['log_monitoring']['success_pattern']
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.get_container_ip(decoy['vmid']) if decoy['type'] == 'lxc' else self.get_vm_ip(decoy['vmid']),
                        username='root',
                        password=decoy['root_password'])
            
            _, stdout, _ = ssh.exec_command(f"tail -n 1000 {log_file}")
            log_content = stdout.read().decode('utf-8')
            
            ssh.close()
            
            matches = re.finditer(success_pattern, log_content)
            for match in matches:
                self.logger.warning(f"Suspicious activity detected on decoy {decoy['name']} (VMID: {decoy['vmid']})")
                self.logger.warning(f"Matched log entry: {match.group(0)}")
            
            decoy['last_check'] = time.time()
        except Exception as e:
            self.logger.error(f"Error monitoring logs for decoy {decoy['name']}: {e}")

    def monitor_decoys(self):
        """
        Monitor all decoy services for suspicious activity.
        """
        for decoy in self.decoy_services:
            if time.time() - decoy.get('last_check', 0) >= decoy['log_monitoring']['check_interval']:
                self.monitor_decoy_logs(decoy)

    def run(self):
        """
        Main execution loop for the ProxmoxMovingCastle controller.
        """
        while True:
            try:
                for service in self.production_services:
                    if time.time() - service.get('last_rotation', 0) >= self.pmc_config['rotation_interval']:
                        self.rotate_production_service(service)
                        service['last_rotation'] = time.time()
                
                for decoy in self.decoy_services:
                    if time.time() - decoy.get('last_recycle', 0) >= self.pmc_config['recycle_interval']:
                        self.recycle_decoy_service(decoy)
                        decoy['last_recycle'] = time.time()
                
                self.monitor_decoys()
                
                time.sleep(60)  # Check every minute
            except Exception as e:
                self.logger.error(f"An error occurred in the main loop: {e}")
                time.sleep(60)  # Wait a bit before retrying

def parse_arguments():
    """
    Parse command line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(description="Proxmox Moving Castle (PMC) Controller",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--pmc-config", default="pmc_config.yaml",
                        help="Path to the PMC configuration file (default: pmc_config.yaml)")
    parser.add_argument("--instances-config", default="instances_config.yaml",
                        help="Path to the instances configuration file (default: instances_config.yaml)")
    return parser.parse_args()

def main():
    """
    Main entry point for the Proxmox Moving Castle controller.
    """
    args = parse_arguments()
    pmc = ProxmoxMovingCastle(args.pmc_config, args.instances_config)
    pmc.run()

if __name__ == "__main__":
    main()
