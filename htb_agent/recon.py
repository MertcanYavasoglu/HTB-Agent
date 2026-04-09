import subprocess
import os
import re
from typing import Optional, Dict
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

def run_nmap(ip: str, args: Optional[str] = None) -> str:
    nmap_args = args if args else os.environ.get("NMAP_DEFAULT_ARGS", "-sV -sC")
    command = ["sudo", "nmap"] + nmap_args.split() + [ip]
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

def run_ffuf_smart(base_command: list) -> str:
    max_duplicates = 100
    ignored_codes = set()
    
    while True:
        current_command = base_command.copy()
        if ignored_codes:
            fc_idx = -1
            for i, arg in enumerate(current_command):
                if arg == "-fc":
                    fc_idx = i
                    break
            
            if fc_idx != -1:
                current_command[fc_idx + 1] = f"{current_command[fc_idx + 1]},{','.join(ignored_codes)}"
            else:
                current_command.extend(["-fc", ",".join(ignored_codes)])

        console.print(f"[bold blue][*] Executing FFUF:[/bold blue] {' '.join(current_command)}")
        process = subprocess.Popen(current_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        status_counts = {}
        should_restart = False
        restarted_code = None
        current_output = []
        
        for line in iter(process.stdout.readline, ''):
            match = re.search(r"\[Status:\s*(\d+)", line)
            if match:
                current_output.append(line)
                code = match.group(1)
                status_counts[code] = status_counts.get(code, 0) + 1
                
                if status_counts[code] >= max_duplicates:
                    should_restart = True
                    restarted_code = code
                    process.terminate()
                    break

        process.wait()
        
        if should_restart:
            console.print(f"[bold yellow][!] FFUF Auto-Filter: Dected {max_duplicates}+ responses with status {restarted_code}. It's a false positive. Filtering {restarted_code} and restarting the scan...[/bold yellow]")
            ignored_codes.add(restarted_code)
            continue
        else:
            return "".join(current_output)


def run_ffuf_subdomain(ip: str, domain: str, wordlist: str) -> str:
    if not os.path.exists(wordlist):
        return f"Error: Wordlist not found: {wordlist}"
        
    ffuf_args = os.environ.get("FFUF_SUB_ARGS", "-mc 200,204,301,302,307,401,403 -fc 404")
    command = [
        "ffuf", "-w", wordlist, 
        "-u", f"http://{ip}", 
        "-H", f"Host: FUZZ.{domain}"
    ] + ffuf_args.split()
    
    try:
        return run_ffuf_smart(command)
    except FileNotFoundError:
        return "Error: ffuf not found"
    except Exception as e:
        return f"Error: {e}"

def run_ffuf_dir(url: str, wordlist: str) -> str:
    if not os.path.exists(wordlist):
        return f"Error: Wordlist not found: {wordlist}"
        
    ffuf_args = os.environ.get("FFUF_DIR_ARGS", "-mc 200,204,301,302,307,401,403")
    command = ["ffuf", "-w", wordlist, "-u", f"{url}/FUZZ"] + ffuf_args.split()
    
    try:
        return run_ffuf_smart(command)
    except FileNotFoundError:
        return "Error: ffuf not found"
    except Exception as e:
        return f"Error: {e}"
        
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
                future_dir = executor.submit(run_ffuf_dir, url, wordlist_dir)
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
