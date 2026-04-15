import subprocess
import os
import re
import asyncio
import shutil
import xml.etree.ElementTree as ET
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

async def run_nmap(ip: str, ports: list[int] = None, args: Optional[str] = None) -> tuple[str, dict]:
    nmap_args = args if args else os.environ.get("NMAP_DEFAULT_ARGS", "-sV -sC")
    command = ["sudo", "nmap"] + nmap_args.split()
    if ports:
        command += ["-p", ",".join(map(str, ports))]
        
    xml_file = f"nmap_{ip}.xml"
    txt_file = f"nmap_{ip}.txt"
    command += ["-oX", xml_file, "-oN", txt_file, ip]
    
    console.print(f"[bold blue][*] Running Deep Nmap:[/bold blue] {' '.join(command)}")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(description="Deep scanning services...", total=None)
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if process.returncode != 0:
                decoded_stderr = stderr.decode('utf-8', errors='replace')
                console.print(f"[bold red][X] Nmap error: {decoded_stderr}[/bold red]")
                
            # Parse XML
            parsed_data = {"ports": {}}
            try:
                if os.path.exists(xml_file):
                    tree = ET.parse(xml_file)
                    root = tree.getroot()
                    for host in root.findall('host'):
                        ports_el = host.find('ports')
                        if ports_el:
                            for port in ports_el.findall('port'):
                                port_id = int(port.get('portid'))
                                state_el = port.find('state')
                                state = state_el.get('state') if state_el is not None else 'unknown'
                                
                                service_el = port.find('service')
                                service_name = service_el.get('name') if service_el is not None else 'unknown'
                                version = service_el.get('version') if service_el is not None else ''
                                product = service_el.get('product') if service_el is not None else ''
                                
                                scripts = {}
                                for script in port.findall('script'):
                                    scripts[script.get('id')] = script.get('output')
                                    
                                parsed_data["ports"][port_id] = {
                                    "state": state,
                                    "service": service_name,
                                    "product": product,
                                    "version": version,
                                    "scripts": scripts
                                }
            except Exception as e:
                console.print(f"[bold red][X] XML Parsing Error: {e}[/bold red]")
                
            try:
                with open(txt_file, "r") as tf:
                    raw_text = tf.read()
            except:
                raw_text = stdout.decode('utf-8', errors='replace')
                
            return raw_text, parsed_data
            
        except FileNotFoundError:
            console.print("[bold red][X] Nmap not found. Install it first.[/bold red]")
            return "Error: nmap not found", {}
        except Exception as e:
            return f"Error: {e}", {}
            
async def trigger_service_enumerations(parsed_data: dict, ip: str, domain: str) -> dict:
    service_results = {}
    tasks = {}
    
    async def run_cmd_async(cmd_list: list, task_name: str) -> str:
        console.print(f"[bold cyan][*] External Trigger ({task_name}):[/bold cyan] {' '.join(cmd_list)}")
        try:
            p = await asyncio.create_subprocess_exec(
                *cmd_list,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )
            stdout, _ = await p.communicate()
            return stdout.decode('utf-8', errors='ignore')
        except Exception as e:
            return f"Error executing {task_name}: {e}"

    target = domain if domain else ip

    for port, info in parsed_data.get("ports", {}).items():
        if info["state"] != "open":
            continue
            
        service_name = info.get("service", "")
        
        # 1. SMB / RPC
        if port in (139, 445) or "smb" in service_name or "netbios" in service_name:
            if shutil.which("enum4linux-ng"):
                tasks["enum4linux"] = asyncio.create_task(run_cmd_async(["enum4linux-ng", "-A", ip], "enum4linux-ng"))
            elif shutil.which("netexec"):
                tasks["netexec_smb"] = asyncio.create_task(run_cmd_async(["netexec", "smb", ip], "netexec"))
            
        # 2. WEB (nuclei / whatweb)
        if port in (80, 443, 8080, 8000, 8443) or "http" in service_name:
            scheme = "https" if port in (443, 8443) or "https" in service_name else "http"
            url = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"
            if shutil.which("nuclei"):
                # Limited fast templates (technologies and cves)
                tasks[f"nuclei_{port}"] = asyncio.create_task(run_cmd_async(["nuclei", "-u", url, "-t", "technologies,cves", "-silent"], f"nuclei on {url}"))
            if shutil.which("whatweb"):
                tasks[f"whatweb_{port}"] = asyncio.create_task(run_cmd_async(["whatweb", url], f"whatweb on {url}"))

        # 3. DNS (Zone Transfer)
        if port == 53 or "domain" in service_name:
            if domain:
                tasks["dig_axfr"] = asyncio.create_task(run_cmd_async(["dig", "axfr", f"@{ip}", target], "dig axfr"))

        # 4. Databases
        if port in (3306, 5432, 1433) or service_name in ("mysql", "postgresql", "ms-sql-s"):
            if port == 3306 or "mysql" in service_name:
                script = "mysql-info,mysql-empty-password"
            elif port == 5432 or "postgres" in service_name:
                script = "pgsql-brute" 
            elif port == 1433 or "ms-sql" in service_name:
                script = "ms-sql-info,ms-sql-empty-password"
            else:
                script = None
                
            if script:
                tasks[f"nmap_db_{port}"] = asyncio.create_task(run_cmd_async([
                    "sudo", "nmap", "-p", str(port), f"--script={script}", ip
                ], f"database scripts on {port}"))

    if tasks:
        await asyncio.gather(*tasks.values())
        for k, v in tasks.items():
            service_results[k] = v.result()
            
    return service_results

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
            
    # Await FFUF tasks separately or collect them
    await asyncio.gather(*tasks.values())
    
    raw_nmap, parsed_nmap = tasks["nmap"].result()
    results["nmap"] = raw_nmap
    results["nmap_json"] = parsed_nmap
    
    # Trigger secondary scripts based on Nmap XML context
    service_enum_results = await trigger_service_enumerations(parsed_nmap, ip, domain)
    results["service_enumerations"] = service_enum_results
    
    results["directories"] = {}
    for port in web_ports:
        if f"dir_{port}" in tasks:
            results["directories"][port] = tasks[f"dir_{port}"].result()
            
    results["subdomains"] = {}
    for port in web_ports:
         if f"sub_{port}" in tasks:
            results["subdomains"][port] = tasks[f"sub_{port}"].result()
        
    return results

