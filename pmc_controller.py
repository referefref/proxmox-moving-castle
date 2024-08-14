#!/usr/bin/env python3

"""
Proxmox Moving Castle (PMC) Controller

This script implements a moving target defense system for Proxmox environments.
It manages the creation, rotation, and monitoring of both production and decoy services
using LXC containers and full VMs, with support for randomized multiple decoys.

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
        self.decoy_instances = self.initialize_decoy_instances()
        self.last_adjust_time = time.time()

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

    def initialize_decoy_instances(self):
        """Initialize decoy instances based on the configuration."""
        decoy_instances = []
        for decoy in self.decoy_services:
            num_instances = random.randint(decoy['min_instances'], decoy['max_instances'])
            for i in range(num_instances):
                instance = decoy.copy()
                instance['name'] = f"{decoy['name']}_{i}"
                instance['port'] = random.randint(decoy['port_range']['start'], decoy['port_range']['end'])
                instance['vmid'] = self.create_decoy_instance(instance)
                decoy_instances.append(instance)
        return decoy_instances

    def create_decoy_instance(self, instance):
        """Create a new decoy instance."""
        if instance['type'] == 'lxc':
            return self.create_lxc(instance['name'], instance['template'], instance['cpu'], instance['memory'])
        else:
            return self.create_vm(instance['name'], instance['template'], instance['cpu'], instance['memory'])

    def recycle_decoy_service(self, instance):
        """
        Recycle a decoy service by creating a new instance and removing the old one.

        Args:
            instance (dict): Decoy instance configuration dictionary.
        """
        self.delete_container(instance['vmid']) if instance['type'] == 'lxc' else self.delete_vm(instance['vmid'])
        
        new_vmid = self.create_decoy_instance(instance)
        
        if new_vmid is None:
            self.logger.error(f"Failed to create new instance for decoy {instance['name']}")
            return

        self.start_container(new_vmid) if instance['type'] == 'lxc' else self.start_vm(new_vmid)
        
        instance['vmid'] = new_vmid
        instance['port'] = random.randint(instance['port_range']['start'], instance['port_range']['end'])
        instance['last_check'] = time.time()
        self.logger.info(f"Recycled decoy service {instance['name']} to new VMID {new_vmid} and port {instance['port']}")

    def adjust_decoy_instances(self):
        """Adjust the number of decoy instances for each decoy service."""
        for decoy in self.decoy_services:
            current_instances = [i for i in self.decoy_instances if i['name'].startswith(decoy['name'])]
            desired_instances = random.randint(decoy['min_instances'], decoy['max_instances'])
            
            if len(current_instances) < desired_instances:
                for _ in range(desired_instances - len(current_instances)):
                    new_instance = decoy.copy()
                    new_instance['name'] = f"{decoy['name']}_{len(current_instances)}"
                    new_instance['port'] = random.randint(decoy['port_range']['start'], decoy['port_range']['end'])
                    new_instance['vmid'] = self.create_decoy_instance(new_instance)
                    self.decoy_instances.append(new_instance)
            elif len(current_instances) > desired_instances:
                for instance in current_instances[desired_instances:]:
                    self.delete_container(instance['vmid']) if instance['type'] == 'lxc' else self.delete_vm(instance['vmid'])
                    self.decoy_instances.remove(instance)

    def monitor_decoy_logs(self, instance):
        """
        Monitor the logs of a decoy service for suspicious activity.

        Args:
            instance (dict): Decoy instance configuration dictionary.
        """
        try:
            log_file = instance['log_monitoring']['log_file']
            success_pattern = instance['log_monitoring']['success_pattern']
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.get_container_ip(instance['vmid']) if instance['type'] == 'lxc' else self.get_vm_ip(instance['vmid']),
                        username='root',
                        password=instance['root_password'])
            
            _, stdout, _ = ssh.exec_command(f"tail -n 1000 {log_file}")
            log_content = stdout.read().decode('utf-8')
            
            ssh.close()
            
            matches = re.finditer(success_pattern, log_content)
            for match in matches:
                self.logger.warning(f"Suspicious activity detected on decoy {instance['name']} (VMID: {instance['vmid']})")
                self.logger.warning(f"Matched log entry: {match.group(0)}")
            
            instance['last_check'] = time.time()
        except Exception as e:
            self.logger.error(f"Error monitoring logs for decoy {instance['name']}: {e}")

    def monitor_decoys(self):
        """Monitor all decoy services for suspicious activity."""
        for instance in self.decoy_instances:
            if time.time() - instance.get('last_check', 0) >= instance['log_monitoring']['check_interval']:
                self.monitor_decoy_logs(instance)

    def run(self):
        """Main execution loop for the ProxmoxMovingCastle controller."""
        while True:
            try:
                # Rotate production services
                for service in self.production_services:
                    if time.time() - service.get('last_rotation', 0) >= self.pmc_config['rotation_interval']:
                        self.rotate_production_service(service)
                        service['last_rotation'] = time.time()
                
                # Recycle decoy services
                for instance in self.decoy_instances:
                    if time.time() - instance.get('last_recycle', 0) >= self.pmc_config['recycle_interval']:
                        self.recycle_decoy_service(instance)
                        instance['last_recycle'] = time.time()
                
                # Adjust decoy instances
                if time.time() - self.last_adjust_time >= self.pmc_config['adjust_interval']:
                    self.adjust_decoy_instances()
                    self.last_adjust_time = time.time()
                
                # Monitor decoys
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
    """Main entry point for the Proxmox Moving Castle controller."""
    args = parse_arguments()
    pmc = ProxmoxMovingCastle(args.pmc_config, args.instances_config)
    pmc.run()

if __name__ == "__main__":
    main()
