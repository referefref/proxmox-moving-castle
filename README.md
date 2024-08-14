# Proxmox Moving Castle (PMC)

Proxmox Moving Castle (PMC) is an advanced moving target defense system designed to work with Proxmox Virtual Environment. It creates a dynamic, constantly shifting landscape of production and decoy services using both LXC containers and full virtual machines, making it extremely difficult for attackers to gain a foothold in your infrastructure.

## Features

- Dynamic port mapping through a centralized router VM
- Automatic rotation of production services to new internal IPs and ports
- Creation and recycling of decoy services to confuse and detect potential attackers
- Monitoring and alerting system for compromise attempts on decoy services
- Full integration with Proxmox API for container and VM management
- Support for both LXC containers and full VMs

## Requirements

- Proxmox Virtual Environment 6.x or later
- Python 3.7 or later
- Access to Proxmox API

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/referefref/proxmox-moving-castle.git
   cd proxmox_moving_castle
   ```

2. Install the required Python packages:
   ```
   pip install -r requirements.txt
   ```

3. Run the setup script to create the initial configuration and set up the router VM:
   ```
   python pmc_setup.py
   ```

4. Follow the prompts to enter your Proxmox and network details.

## Configuration

PMC uses two main configuration files:

1. `pmc_config.yaml`: Contains Proxmox connection details and global settings.
2. `instances_config.yaml`: Defines the specific production and decoy services.

The `pmc_setup.py` script will generate a basic `pmc_config.yaml` file. You'll need to manually create or edit the `instances_config.yaml` file to define your services.

Example configuration files can be found in the `config_examples` folder.

### pmc_config.yaml

```yaml
proxmox:
  host: 'your_proxmox_host'
  user: 'root@pam'
  password: 'your_password'
  node: 'pve'
  storage: 'local'

router_vm_id: 100

router:
  ip: '192.168.1.1'
  user: 'root'
  password: 'router_password'

production_port_range:
  start: 30000
  end: 40000

decoy_port_range:
  start: 40001
  end: 50000

rotation_interval: 3600  # in seconds
recycle_interval: 1800  # in seconds
```

### instances_config.yaml

```yaml
production_services:
  - name: 'web_server'
    type: 'lxc'
    template: 'local:vztmpl/ubuntu-20.04-standard_20.04-1_amd64.tar.gz'
    cpu: 1
    memory: 512
    internal_port: 80

decoy_services:
  - name: 'decoy_ssh'
    type: 'lxc'
    template: 'local:vztmpl/ubuntu-20.04-standard_20.04-1_amd64.tar.gz'
    cpu: 1
    memory: 256
```

## Usage

After setting up the configuration files, you can start the Proxmox Moving Castle system:

```
python pmc_controller.py
```

This will start the main control loop, which will:

1. Create and manage production services
2. Create and recycle decoy services
3. Rotate production services periodically
4. Monitor decoy services for signs of compromise

## How It Works

1. **Router VM**: Acts as the central point for incoming connections, dynamically mapping external ports to internal services.

2. **Production Services**: Real services that are periodically moved to new internal IPs and ports. The router VM updates its port forwarding rules to maintain accessibility.

3. **Decoy Services**: Fake services that mimic production services but with intentionally weak security. These are regularly recycled and monitored for any access attempts.

4. **Rotation**: Production services are periodically moved to new internal addresses, making it difficult for an attacker to maintain persistence.

5. **Recycling**: Decoy services are regularly destroyed and recreated with new credentials and on different ports.

6. **Monitoring**: The system continuously monitors decoy services for any signs of compromise, providing early warning of potential attacks.

## Security Considerations

- Ensure your Proxmox environment is properly secured.
- Regularly update the router VM and all service templates.
- Monitor the PMC logs for any suspicious activities.
- This system is designed to complement, not replace, other security measures.

## Contributing

Contributions to Proxmox Moving Castle are welcome! Please feel free to submit pull requests, create issues, or suggest new features.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

Proxmox Moving Castle is provided as-is, without any guarantees or warranty. The authors are not responsible for any damage or data loss incurred from using this software.