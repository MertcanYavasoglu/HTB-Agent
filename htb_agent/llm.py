import os
import ollama
import asyncio
from rich.console import Console
from rich.markdown import Markdown
from typing import Dict, Optional, List

console = Console()

def get_ollama_model() -> str:
    return os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b")

async def analyze_recon(results: Dict[str, str], crawl_data: List[Dict[str, str]] = None) -> str:
    model = get_ollama_model()
    
    # Format crawl data into string
    extra_web_context = ""
    if crawl_data:
        extra_web_context = "\n[WEB CRAWL DATA]\n"
        for page in crawl_data:
            extra_web_context += f"--- Page: {page['name']} ({page['url']}) ---\n"
            extra_web_context += f"Title: {page['title']}\n"
            extra_web_context += f"Content Snippet: {page['content'][:2000]}...\n" # Limit each page content
            if page.get('links'):
                extra_web_context += "Interactive Elements found: " + ", ".join([l['text'] for l in page['links'] if l['text']]) + "\n\n"

    prompt = f"""
You are an expert Penetration Tester. Analyze the reconnaissance data for a Hack The Box target.
Provide a summary of vulnerabilities, exploitation steps, and exact bash commands to run.

[NMAP RESULTS]
{results.get('nmap', 'No nmap data.')}

[FFUF DIRECTORY RESULTS]
{results.get('directories', 'No directory data.')}

[FFUF SUBDOMAIN RESULTS]
{results.get('subdomains', 'No subdomain data.')}
{extra_web_context}

Be concise, technical, and use Markdown.
"""
    
    console.print(f"[bold purple][*] Analyzing with local Ollama ({model})...[/bold purple]")
    client = ollama.AsyncClient()
    try:
        response = await client.chat(model=model, messages=[
            {'role': 'user', 'content': prompt}
        ])
        return response['message']['content']
    except Exception as e:
        if "not found" in str(e).lower():
            console.print(f"[bold red][X] Ollama Model '{model}' not found. Run 'ollama pull {model}' first.[/bold red]")
        else:
            console.print(f"[bold red][X] Ollama Error: {e}[/bold red]")
        return str(e)

async def chat_loop(initial_context: str):
    model = get_ollama_model()
    
    console.print("\n[bold green]=== Interactive Chat Mode (Ollama) ===[/bold green]")
    console.print("[italic]Type 'q', 'quit', or 'exit' to leave.[/italic]\n")
    
    messages = [
        {'role': 'system', 'content': "You are an expert penetration tester assisting a user with a CTF/HTB target. Be concise and technical."},
        {'role': 'user', 'content': f"Here is the context for the target:\n{initial_context}"}
    ]
    
    client = ollama.AsyncClient()
    
    # Try to prime the model
    try:
        await client.chat(model=model, messages=messages)
    except Exception as e:
        console.print(f"[bold red][X] Failed to connect to Ollama: {e}[/bold red]")
        return
        
    while True:
        try:
            user_input = await asyncio.to_thread(console.input, "[bold yellow]You >[/bold yellow] ")
            if user_input.strip().lower() in ['q', 'quit', 'exit']:
                break
            
            messages.append({'role': 'user', 'content': user_input})
            
            # Show a thinking indicator? Ollama is local and can take time.
            with console.status(f"[bold cyan]Ollama ({model}) is thinking...[/bold cyan]"):
                response = await client.chat(model=model, messages=messages)
            
            assistant_msg = response['message']['content']
            messages.append({'role': 'assistant', 'content': assistant_msg})
            
            console.print("\n[bold purple]Agent >[/bold purple]")
            console.print(Markdown(assistant_msg))
            console.print("")
        except (KeyboardInterrupt, EOFError):
            break
        except Exception as e:
            console.print(f"[bold red][X] Error: {e}[/bold red]")
