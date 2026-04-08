import typer
from rich.console import Console
from rich.markdown import Markdown
from dotenv import load_dotenv
import os

from htb_agent.system import add_to_hosts
from htb_agent.recon import perform_full_recon
from htb_agent.vision import crawl_text_content
from htb_agent.llm import analyze_recon, chat_loop

load_dotenv()
app = typer.Typer(help="HTB Recon & Analysis Agent")
console = Console()

@app.command()
def start(
    ip: str = typer.Option(..., "-i", "--ip", help="Target IP address"),
    domain: str = typer.Option(None, "-d", "--domain", help="Target Domain"),
    wordlist: str = typer.Option(os.environ.get("WORDLIST_DIRS", ""), "-w", "--wordlist", help="Wordlist for directory bruteforce"),
    sub_wordlist: str = typer.Option(os.environ.get("WORDLIST_SUBDOMAINS", ""), "--sub-wordlist", help="Wordlist for subdomain bruteforce"),
    hosts: bool = typer.Option(True, "--hosts/--no-hosts", help="Add to /etc/hosts"),
    chat: bool = typer.Option(True, "--chat/--no-chat", help="Start interactive chat after analysis")
):
    console.print(f"\n[bold green][+] Target initialized: {ip} {f'({domain})' if domain else ''}[/bold green]\n")
    
    if hosts and domain:
        add_to_hosts(ip, domain)

    results = perform_full_recon(ip, domain, wordlist, sub_wordlist)
    
    crawl_data = []
    http_open = "80/tcp" in results.get("nmap", "") or "443/tcp" in results.get("nmap", "") or "http" in results.get("nmap", "")
    
    if http_open or (domain and results.get("directories") != "Skipped directory scan."):
        target_url = f"http://{domain}" if domain else f"http://{ip}"
        if "443/tcp" in results.get("nmap", "") and "80/tcp" not in results.get("nmap", ""):
            target_url = f"https://{domain}" if domain else f"https://{ip}"
        
        crawl_data = crawl_text_content(target_url)
        
    analysis_text = analyze_recon(results, crawl_data)
    
    console.print("\n[bold cyan]=== AGENT REPORT ===[/bold cyan]")
    console.print(Markdown(analysis_text))
    console.print("\n[bold cyan]====================[/bold cyan]")
    
    report_file = f"writeup_{domain if domain else ip}.md"
    try:
        with open(report_file, "w") as f:
            f.write(f"# Target: {domain if domain else ip}\n\n")
            f.write("## 1. Nmap Scan\n```text\n" + results.get("nmap", "") + "\n```\n\n")
            f.write("## 2. Directories Found\n```text\n" + results.get("directories", "") + "\n```\n\n")
            f.write("## 3. Subdomains Found\n```text\n" + results.get("subdomains", "") + "\n```\n\n")
            f.write("## 4. Vulnerability Analysis\n\n" + analysis_text)
        console.print(f"[green][+] Writeup drafted: {report_file}[/green]")
    except Exception as e:
        console.print(f"[bold red][X] Failed to save writeup: {e}[/bold red]")
        
    if chat:
        chat_context = f"Target: {ip} ({domain})\nNmap: {results.get('nmap')}\nDirectories: {results.get('directories')}\nSubdomains: {results.get('subdomains')}\nReport: {analysis_text}"
        chat_loop(chat_context)

if __name__ == "__main__":
    app()
