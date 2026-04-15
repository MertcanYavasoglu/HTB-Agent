import os
import subprocess
import sys

from rich.console import Console

console = Console()

def ensure_sudo():
    """Ensure we have sudo privileges early on so future commands don't hang waiting for password."""
    try:
        console.print("[cyan][*] Requesting sudo privileges for nmap and /etc/hosts modifications...[/cyan]")
        subprocess.run(["sudo", "-v"], check=True)
    except subprocess.CalledProcessError:
        console.print("[bold red][X] Sudo authentication failed or was cancelled. Exiting.[/bold red]")
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(1)

def add_to_hosts(ip: str, domain: str):
    hosts_path = "/etc/hosts"
    
    try:
        with open(hosts_path, "r") as f:
            lines = f.readlines()
            
        domain_found = False
        ip_matches = False
        new_lines = []
        
        for line in lines:
            if not line.strip() or line.strip().startswith('#'):
                new_lines.append(line)
                continue
                
            parts = line.strip().split()
            if len(parts) >= 2 and domain in parts[1:]:
                domain_found = True
                if parts[0] == ip:
                    ip_matches = True
                    new_lines.append(line)
                else:
                    console.print(f"[yellow][!] {domain} found with different IP ({parts[0]}). Updating to {ip}...[/yellow]")
                    parts[0] = ip
                    new_lines.append("\t".join(parts) + "\n")
            else:
                new_lines.append(line)

        if domain_found and ip_matches:
            console.print(f"[yellow][!] {domain} already in /etc/hosts with correct IP.[/yellow]")
            return True
            
        if not domain_found:
            console.print(f"[cyan][*] Adding {domain} to /etc/hosts...[/cyan]")
            new_lines.append(f"{ip}\t{domain}\n")
            
        new_content = "".join(new_lines)
        
        try:
            subprocess.run(
                ["sudo", "tee", hosts_path],
                input=new_content.encode(),
                stdout=subprocess.DEVNULL,
                check=True
            )
            console.print(f"[green][+] /etc/hosts updated mapping {domain} to {ip}.[/green]")
            return True
        except subprocess.CalledProcessError as e:
            console.print(f"[bold red][X] Failed to update hosts: {e}[/bold red]")
            return False

    except PermissionError:
        console.print("[bold red][X] Permission denied for /etc/hosts. Run with sudo.[/bold red]")
        return False
    except Exception as e:
        console.print(f"[bold red][X] Hosts file error: {e}[/bold red]")
        return False
