import os
from typing import List, Dict
from rich.console import Console
from playwright.async_api import async_playwright

console = Console()

async def crawl_text_content(url: str) -> List[Dict[str, str]]:
    max_clicks = int(os.environ.get("MAX_CRAWL_PAGES", "3"))
    console.print(f"[bold blue][*] Crawling up to {max_clicks + 1} pages for text content starting at:[/bold blue] {url}")
    
    extracted_data = []
    
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True, 
                args=['--disable-dev-shm-usage', '--no-sandbox', '--disable-gpu']
            )
            page = await browser.new_page(ignore_https_errors=True)
            
            async def get_page_info(p_name: str):
                return {
                    "url": page.url,
                    "name": p_name,
                    "title": await page.title(),
                    "content": await page.evaluate("() => document.body.innerText"),
                    # Summary of interactive elements to help Qwen understand the UI
                    "links": await page.evaluate("""() => {
                        return Array.from(document.querySelectorAll('a, button'))
                            .filter(el => el.offsetWidth > 0 && el.offsetHeight > 0)
                            .map(el => ({
                                text: (el.innerText || el.value || '').trim(),
                                href: el.href || '',
                                tag: el.tagName.toLowerCase()
                            })).slice(0, 20); // Limit to top 20 for context
                    }""")
                }

            console.print("[*] Loading main page...")
            await page.goto(url, wait_until="networkidle", timeout=15000)
            extracted_data.append(await get_page_info("Home Page"))
            
            keywords = ['login', 'admin', 'dashboard', 'register', 'portal', 'sign', 'auth', 'account']
            
            links_data = await page.evaluate("""
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
            
            seen_hrefs = {url}
            unique_targets = []
            for score, item in prioritized:
                key = item['href'] if item['href'] else item['text']
                if key not in seen_hrefs:
                    seen_hrefs.add(key)
                    unique_targets.append(item)
                    
            targets_to_click = unique_targets[:max_clicks]
            if targets_to_click:
                console.print(f"[*] Found {len(targets_to_click)} actionable context links. Crawling text...")
            
            for i, target in enumerate(targets_to_click):
                target_name = target['text'] if len(target['text']) > 0 else 'element'
                console.print(f"[*] Extracting text from '{target_name}'...")
                try:
                    if target['tag'] == 'a' and target['href']:
                        await page.goto(target['href'], wait_until="networkidle", timeout=15000)
                    else:
                        await page.evaluate(f"document.querySelectorAll('a, button')[{target['index']}].click()")
                        await page.wait_for_load_state("networkidle", timeout=10000)
                    
                    extracted_data.append(await get_page_info(target_name))
                    await page.goto(url, wait_until="networkidle", timeout=15000)
                except Exception as ex:
                    console.print(f"[yellow][!] Could not process '{target_name}': {ex}[/yellow]")
                    try:
                        await page.goto(url, wait_until="networkidle", timeout=10000)
                    except:
                        pass
                
            await browser.close()
            return extracted_data
            
    except Exception as e:
        console.print(f"[bold red][X] Vision crawl error: {e}[/bold red]")
        return extracted_data
