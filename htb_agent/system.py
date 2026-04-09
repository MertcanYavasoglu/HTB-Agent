import os
import subprocess

from rich.console import Console

console = Console()

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
