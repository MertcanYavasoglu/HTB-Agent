import subprocess
import os
import re
import asyncio
import shutil
from typing import Optional, Dict

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

async def run_fast_scan(ip: str) -> list[int]:
    ports = set()
    if shutil.which("rustscan"):
        # We must make sure Rustscan terminates securely, the old flag sequence failed in newer versions
        command = ["rustscan", "-a", ip, "-t", "1000", "-g"]
        console.print(f"[bold blue][*] Running fast initial port scan with RustScan on {ip}...[/bold blue]")
    elif shutil.which("masscan"):
        command = ["sudo", "masscan", "-p1-65535", ip, "--rate=10000"]
        console.print(f"[bold blue][*] Running fast initial port scan with Masscan on {ip}...[/bold blue]")
    else:
        command = ["sudo", "nmap", "-p-", "--min-rate", "10000", "-T4", ip]
        console.print(f"[bold blue][*] Running fast initial port scan with Nmap (-p- --min-rate 10000) on {ip}...[/bold blue]")
        
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        output = stdout.decode('utf-8', errors='ignore') + stderr.decode('utf-8', errors='ignore')
        
        for line in output.split("\n"):
            # Standard Nmap or Masscan
            match = re.search(r"(\d+)/tcp\s+open", line)
            if match:
                ports.add(int(match.group(1)))
            # Masscan specific line
            match2 = re.search(r"Discovered open port (\d+)/tcp", line)
            if match2:
                ports.add(int(match2.group(1)))
            # RustScan direct line parsing
            match3 = re.search(r"Open\s+[0-9\.]+[:\s]+(\d+)", line)
            if match3:
                ports.add(int(match3.group(1)))
            # Rustscan -g outputs: 10.10.10.10 -> [80, 22] or similar format
            match_g = re.search(r"->\s*\[(.*?)\]", line)
            if match_g:
                port_list = match_g.group(1)
                for p in port_list.split(","):
                    p = p.strip()
                    if p.isdigit():
                        ports.add(int(p))
                        
    except Exception as e:
        console.print(f"[bold red][X] Fast scan failed: {e}[/bold red]")
        
    return sorted(list(ports))

async def run_nmap(ip: str, ports: list[int] = None, args: Optional[str] = None) -> str:
    nmap_args = args if args else os.environ.get("NMAP_DEFAULT_ARGS", "-sV -sC")
    command = ["sudo", "nmap"] + nmap_args.split()
    if ports:
        command += ["-p", ",".join(map(str, ports))]
    command += [ip]
    console.print(f"[bold blue][*] Running Nmap:[/bold blue] {' '.join(command)}")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(description="Scanning ports...", total=None)
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if process.returncode != 0:
                decoded_stderr = stderr.decode('utf-8', errors='replace')
                decoded_stdout = stdout.decode('utf-8', errors='replace')
                console.print(f"[bold red][X] Nmap error: {decoded_stderr}[/bold red]")
                return decoded_stdout if decoded_stdout else f"Error: {decoded_stderr}"
            return stdout.decode('utf-8', errors='replace')
        except FileNotFoundError:
            console.print("[bold red][X] Nmap not found. Install it first.[/bold red]")
            return "Error: nmap not found"
        except Exception as e:
            return f"Error: {e}"

async def run_ffuf_smart(base_command: list) -> str:
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
        try:
            process = await asyncio.create_subprocess_exec(
                *current_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )
        except Exception as e:
            return f"Error starting FFUF: {e}"
        
        status_counts = {}
        should_restart = False
        restarted_code = None
        current_output = []
        
        while True:
            line_bytes = await process.stdout.readline()
            if not line_bytes:
                break
            line = line_bytes.decode('utf-8', errors='replace')
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

        await process.wait()
        
        if should_restart:
            console.print(f"[bold yellow][!] FFUF Auto-Filter: Dected {max_duplicates}+ responses with status {restarted_code}. It's a false positive. Filtering {restarted_code} and restarting the scan...[/bold yellow]")
            ignored_codes.add(restarted_code)
            continue
        else:
            return "".join(current_output)


async def run_ffuf_subdomain(ip: str, domain: str, wordlist: str, port: int = 80) -> str:
    if not os.path.exists(wordlist):
        return f"Error: Wordlist not found: {wordlist}"
        
    ffuf_args = os.environ.get("FFUF_SUB_ARGS", "-mc 200,204,301,302,307,401,403 -fc 404")
    
    is_https = (port == 443 or port == 8443)
    scheme = "https" if is_https else "http"
    if port == 80 and scheme == "http":
        url = f"{scheme}://{ip}"
    elif port == 443 and scheme == "https":
        url = f"{scheme}://{ip}"
    else:
        url = f"{scheme}://{ip}:{port}"
        
    command = [
        "ffuf", "-w", wordlist, 
        "-u", url, 
        "-H", f"Host: FUZZ.{domain}"
    ] + ffuf_args.split()
    
    try:
        return await run_ffuf_smart(command)
    except FileNotFoundError:
        return "Error: ffuf not found"
    except Exception as e:
        return f"Error: {e}"

async def run_ffuf_dir(url: str, wordlist: str) -> str:
    if not os.path.exists(wordlist):
        return f"Error: Wordlist not found: {wordlist}"
        
    ffuf_args = os.environ.get("FFUF_DIR_ARGS", "-mc 200,204,301,302,307,401,403")
    command = ["ffuf", "-w", wordlist, "-u", f"{url}/FUZZ"] + ffuf_args.split()
    
    try:
        return await run_ffuf_smart(command)
    except FileNotFoundError:
        return "Error: ffuf not found"
    except Exception as e:
        return f"Error: {e}"
        

async def perform_full_recon(ip: str, domain: str, wordlist_dir: Optional[str] = None, wordlist_sub: Optional[str] = None):
    results = {}
    
    open_ports = await run_fast_scan(ip)
    results["open_ports"] = open_ports
    
    if not open_ports:
        console.print("[yellow][!] No open ports found during fast scan. Aborting deeper scans.[/yellow]")
        results["nmap"] = "No open ports found."
        results["directories"] = {}
        results["subdomains"] = {}
        return results
        
    console.print(f"[bold green][+] Open ports discovered: {open_ports}[/bold green]")
    
    tasks = {
        "nmap": asyncio.create_task(run_nmap(ip, open_ports))
    }
    
    common_web_ports = {80, 443, 3000, 5000, 8000, 8008, 8080, 8443}
    web_ports = [p for p in open_ports if p in common_web_ports]
    
    dir_tasks = {}
    sub_tasks = {}
    
    for port in web_ports:
        is_https = (port == 443 or port == 8443)
        scheme = "https" if is_https else "http"
        target_domain = domain if domain else ip
        
        if port == 80 and scheme == "http":
            url = f"{scheme}://{target_domain}"
        elif port == 443 and scheme == "https":
            url = f"{scheme}://{target_domain}"
        else:
            url = f"{scheme}://{target_domain}:{port}"
            
        if wordlist_dir:
            dir_tasks[port] = asyncio.create_task(run_ffuf_dir(url, wordlist_dir))
        
        if domain and wordlist_sub:
            sub_tasks[port] = asyncio.create_task(run_ffuf_subdomain(ip, domain, wordlist_sub, port=port))

    for k, v in dir_tasks.items():
        tasks[f"dir_{k}"] = v
    for k, v in sub_tasks.items():
        tasks[f"sub_{k}"] = v
            
    await asyncio.gather(*tasks.values())
    
    results["nmap"] = tasks["nmap"].result()
    
    results["directories"] = {}
    for port in web_ports:
        if f"dir_{port}" in tasks:
            results["directories"][port] = tasks[f"dir_{port}"].result()
            
    results["subdomains"] = {}
    for port in web_ports:
         if f"sub_{port}" in tasks:
            results["subdomains"][port] = tasks[f"sub_{port}"].result()
        
    return results

