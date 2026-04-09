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
    entry = f"{ip}\t{domain}\n"
    
    try:
        with open(hosts_path, "r") as f:
            content = f.read()
            
        if domain in content and ip in content:
            console.print(f"[yellow][!] {domain} already in /etc/hosts.[/yellow]")
            return True
            
        console.print(f"[cyan][*] Adding {domain} to /etc/hosts...[/cyan]")
        
        # Use subprocess to run 'tee -a' with sudo for isolation
        try:
            subprocess.run(
                ["sudo", "tee", "-a", hosts_path],
                input=entry.encode(),
                stdout=subprocess.DEVNULL,
                check=True
            )
            console.print(f"[green][+] {domain} added.[/green]")
            return True
        except subprocess.CalledProcessError as e:
            console.print(f"[bold red][X] Failed to add {domain} to hosts: {e}[/bold red]")
            return False

    except PermissionError:
        console.print("[bold red][X] Permission denied for /etc/hosts. Run with sudo.[/bold red]")
        return False
    except Exception as e:
        console.print(f"[bold red][X] Hosts file error: {e}[/bold red]")
        return False
