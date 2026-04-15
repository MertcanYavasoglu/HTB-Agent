import typer
from rich.console import Console
from rich.markdown import Markdown
from dotenv import load_dotenv
import os
import asyncio

from htb_agent.system import add_to_hosts, ensure_sudo
from htb_agent.recon import perform_full_recon
from htb_agent.vision import crawl_text_content
from htb_agent.llm import analyze_recon, chat_loop

load_dotenv()
app = typer.Typer(help="HTB Recon & Analysis Agent")
console = Console()


async def async_start(ip: str, domain: str, wordlist: str, sub_wordlist: str, hosts: bool, chat: bool):
    console.print(f"\n[bold green][+] Target initialized: {ip} {f'({domain})' if domain else ''}[/bold green]\n")
    
    # Pre-cache user's sudo password to prevent headless hanging later
    ensure_sudo()
    
    if hosts and domain:
        add_to_hosts(ip, domain)

    results = await perform_full_recon(ip, domain, wordlist, sub_wordlist)
    
    open_ports = results.get("open_ports", [])
    common_web_ports = {80, 443, 3000, 5000, 8000, 8008, 8080, 8443}
    web_ports = [p for p in open_ports if p in common_web_ports]
    
    crawl_data = []
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
            
        port_crawl_data = await crawl_text_content(url)
        crawl_data.extend(port_crawl_data)
        
    # Format FFUF outputs for markdown and LLM context
    directories = results.get("directories", {})
    if isinstance(directories, dict):
        dir_str = ""
        for port, res in directories.items():
            dir_str += f"=== Port {port} ===\n{res}\n"
        results["directories"] = dir_str if dir_str else "No directories scanned."
        
    subdomains = results.get("subdomains", {})
    if isinstance(subdomains, dict):
        sub_str = ""
        for port, res in subdomains.items():
            sub_str += f"=== Port {port} ===\n{res}\n"
        results["subdomains"] = sub_str if sub_str else "No subdomains scanned."
        
    analysis_text = await analyze_recon(results, crawl_data)
    
    console.print("\n[bold cyan]=== AGENT REPORT ===[/bold cyan]")
    console.print(Markdown(analysis_text))
    console.print("\n[bold cyan]====================[/bold cyan]")
    
    report_file = f"writeup_{domain if domain else ip}.md"
    try:
        with open(report_file, "w") as f:
            f.write(f"# Target: {domain if domain else ip}\n\n")
            f.write("## 1. Nmap Scan\n```text\n" + str(results.get("nmap", "")) + "\n```\n\n")
            f.write("## 2. Directories Found\n```text\n" + str(results.get("directories", "")) + "\n```\n\n")
            f.write("## 3. Subdomains Found\n```text\n" + str(results.get("subdomains", "")) + "\n```\n\n")
            
            f.write("## 4. Web Content Data (Playwright)\n")
            if crawl_data:
                import json
                f.write("```json\n" + json.dumps(crawl_data, indent=2, ensure_ascii=False) + "\n```\n\n")
            else:
                f.write("```text\nNo web data collected.\n```\n\n")
            
            f.write("## 5. Vulnerability Analysis\n\n" + analysis_text)
        console.print(f"[green][+] Writeup drafted: {report_file}[/green]")
    except Exception as e:
        console.print(f"[bold red][X] Failed to save writeup: {e}[/bold red]")
        
    if chat:
        chat_context = f"Target: {ip} ({domain})\nNmap: {results.get('nmap')}\nDirectories: {results.get('directories')}\nSubdomains: {results.get('subdomains')}\nReport: {analysis_text}"
        await chat_loop(chat_context)

@app.command()
def start(
    ip: str = typer.Option(..., "-i", "--ip", help="Target IP address"),
    domain: str = typer.Option(None, "-d", "--domain", help="Target Domain"),
    wordlist: str = typer.Option(os.environ.get("WORDLIST_DIRS", ""), "-w", "--wordlist", help="Wordlist for directory bruteforce"),
    sub_wordlist: str = typer.Option(os.environ.get("WORDLIST_SUBDOMAINS", ""), "--sub-wordlist", help="Wordlist for subdomain bruteforce"),
    hosts: bool = typer.Option(True, "--hosts/--no-hosts", help="Add to /etc/hosts"),
    chat: bool = typer.Option(True, "--chat/--no-chat", help="Start interactive chat after analysis")
):
    asyncio.run(async_start(ip, domain, wordlist, sub_wordlist, hosts, chat))

if __name__ == "__main__":
    app()
