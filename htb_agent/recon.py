import subprocess
import os
from typing import Optional, Dict
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

def run_nmap(ip: str, args: Optional[str] = None) -> str:
    nmap_args = args if args else os.environ.get("NMAP_DEFAULT_ARGS", "-sV -sC")
    command = ["nmap"] + nmap_args.split() + [ip]
    console.print(f"[bold blue][*] Running Nmap:[/bold blue] {' '.join(command)}")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(description="Scanning ports...", total=None)
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            console.print(f"[bold red][X] Nmap error: {e.stderr}[/bold red]")
            return e.stdout if e.stdout else f"Error: {e.stderr}"
        except FileNotFoundError:
            console.print("[bold red][X] Nmap not found. Install it first.[/bold red]")
            return "Error: nmap not found"

def run_ffuf_subdomain(ip: str, domain: str, wordlist: str) -> str:
    if not os.path.exists(wordlist):
        return f"Error: Wordlist not found: {wordlist}"
        
    command = [
        "ffuf", "-w", wordlist, 
        "-u", f"http://{ip}", 
        "-H", f"Host: FUZZ.{domain}",
        "-mc", "200,301,302", "-s"
    ]
    console.print(f"[bold blue][*] Running ffuf scan:[/bold blue] {' '.join(command)}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return e.stdout if e.stdout else f"Error: {e.stderr}"
    except FileNotFoundError:
        return "Error: ffuf not found"

def run_gobuster_dir(url: str, wordlist: str) -> str:
    if not os.path.exists(wordlist):
        return f"Error: Wordlist not found: {wordlist}"
        
    command = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q"]
    console.print(f"[bold blue][*] Running Gobuster:[/bold blue] {' '.join(command)}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return e.stdout if e.stdout else f"Error: {e.stderr}"
    except FileNotFoundError:
        return "Error: gobuster not found"
        
import concurrent.futures

def perform_full_recon(ip: str, domain: str, wordlist_dir: Optional[str] = None, wordlist_sub: Optional[str] = None):
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        # Submit all tasks simultaneously
        future_nmap = executor.submit(run_nmap, ip)
        
        future_dir = None
        future_sub = None
        
        if domain:
            # We assume HTTP exists and start brute force instantly instead of waiting for Nmap
            url = f"http://{domain}"
            if wordlist_dir:
                future_dir = executor.submit(run_gobuster_dir, url, wordlist_dir)
            if wordlist_sub:
                future_sub = executor.submit(run_ffuf_subdomain, ip, domain, wordlist_sub)
                
        # Wait and collect real results
        results["nmap"] = future_nmap.result()
        
        if future_dir:
            results["directories"] = future_dir.result()
        else:
            results["directories"] = "Skipped directory scan."
            
        if future_sub:
            results["subdomains"] = future_sub.result()
        else:
            results["subdomains"] = "Skipped subdomain scan."
            
    return results
