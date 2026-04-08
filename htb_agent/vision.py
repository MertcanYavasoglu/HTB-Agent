import os
from rich.console import Console
from playwright.sync_api import sync_playwright

console = Console()

from typing import List

def capture_screenshots(url: str) -> List[str]:
    max_clicks = int(os.environ.get("MAX_CRAWL_PAGES", "3"))
    console.print(f"[bold blue][*] Capturing up to {max_clicks + 1} screenshots starting at:[/bold blue] {url}")
    
    screenshots = []
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True, 
                args=['--disable-dev-shm-usage', '--no-sandbox', '--disable-gpu']
            )
            page = browser.new_page(ignore_https_errors=True)
            
            console.print("[*] Loading main page...")
            page.goto(url, wait_until="networkidle", timeout=15000)
            
            main_shot = "htb_screenshot_main.png"
            page.screenshot(path=main_shot)
            screenshots.append(main_shot)
            console.print(f"[green][+] Main screenshot saved: {main_shot}[/green]")
            
            keywords = ['login', 'admin', 'dashboard', 'register', 'portal', 'sign', 'auth', 'account']
            
            links_data = page.evaluate("""
                () => {
                    const elements = Array.from(document.querySelectorAll('a, button'));
                    const results = [];
                    elements.forEach((el, index) => {
                        if (el.offsetWidth > 0 && el.offsetHeight > 0) {
                            let text = (el.innerText || el.value || '').toLowerCase().trim();
                            let href = el.href || '';
                            if (text.length > 0 || href.length > 0) {
                                results.push({index: index, text: text, href: href, tag: el.tagName.toLowerCase()});
                            }
                        }
                    });
                    return results;
                }
            """)
            
            prioritized = []
            for item in links_data:
                if item['tag'] == 'a' and item['href']:
                    domain = url.split("//")[1].split("/")[0]
                    if domain not in item['href'] and item['href'].startswith('http'):
                        continue
                
                score = 0
                for kw in keywords:
                    if kw in item['text'] or kw in item['href'].lower():
                        score += 1
                        
                if score > 0:
                    prioritized.append((score, item))
                    
            prioritized.sort(key=lambda x: x[0], reverse=True)
            
            seen_hrefs = set()
            unique_targets = []
            for score, item in prioritized:
                key = item['href'] if item['href'] else item['text']
                if key not in seen_hrefs:
                    seen_hrefs.add(key)
                    unique_targets.append(item)
                    
            targets_to_click = unique_targets[:max_clicks]
            if targets_to_click:
                console.print(f"[*] Found {len(targets_to_click)} actionable context links. Crawling...")
            
            for i, target in enumerate(targets_to_click):
                target_name = target['text'] if len(target['text']) > 0 else 'element'
                console.print(f"[*] Proceeding to '{target_name}'...")
                try:
                    if target['tag'] == 'a' and target['href']:
                        page.goto(target['href'], wait_until="networkidle", timeout=15000)
                    else:
                        page.evaluate(f"document.querySelectorAll('a, button')[{target['index']}].click()")
                        page.wait_for_load_state("networkidle", timeout=10000)
                        
                    shot_path = f"htb_screenshot_{i+1}.png"
                    page.screenshot(path=shot_path)
                    screenshots.append(shot_path)
                    console.print(f"[green][+] Sub-screenshot saved: {shot_path}[/green]")
                    
                    page.goto(url, wait_until="networkidle", timeout=15000)
                except Exception as ex:
                    console.print(f"[yellow][!] Could not process '{target_name}': {ex}[/yellow]")
                    try:
                        page.goto(url, wait_until="networkidle", timeout=10000)
                    except:
                        pass
                
            browser.close()
            return screenshots
            
    except Exception as e:
        console.print(f"[bold red][X] Vision crawl error: {e}[/bold red]")
        return screenshots
