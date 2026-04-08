import os
from rich.console import Console
from playwright.sync_api import sync_playwright

console = Console()

def capture_screenshot(url: str, output_path: str = "screenshot.png") -> str:
    console.print(f"[bold blue][*] Capturing screenshot:[/bold blue] {url}")
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(ignore_https_errors=True)
            page.goto(url, wait_until="networkidle", timeout=15000)
            page.screenshot(path=output_path, full_page=True)
            browser.close()
            
        console.print(f"[green][+] Screenshot saved: {output_path}[/green]")
        return output_path
    except Exception as e:
        console.print(f"[bold red][X] Screenshot error: {e}[/bold red]")
        return ""
