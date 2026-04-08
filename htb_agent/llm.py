import os
from google import genai
from rich.console import Console
from rich.markdown import Markdown
from typing import Dict, Optional

console = Console()

def get_gemini_client() -> Optional[genai.Client]:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        console.print("[bold red][X] GEMINI_API_KEY not found in environment.[/bold red]")
        return None
    return genai.Client(api_key=api_key)

def analyze_recon(results: Dict[str, str], screenshot_paths: list = None) -> str:
    client = get_gemini_client()
    if not client: return ""
    
    prompt = f"""
You are a Penetration Tester mapping out attack vectors.
Analyze the following reconnaissance data and provide vulnerabilities, potential exploitation steps, and exact bash commands to run for exploitation.
Be concise and clear. Format output in Markdown.

[NMAP RESULTS]
{results.get('nmap', 'No nmap data.')}

[DIRECTORY RESULTS]
{results.get('directories', 'No directory data.')}
"""
    
    contents = [prompt]
    
    if screenshot_paths:
        console.print(f"[cyan][*] Adding {len(screenshot_paths)} screenshots to LLM context...[/cyan]")
        try:
            from google.genai import types
            for path in screenshot_paths:
                if os.path.exists(path):
                    with open(path, "rb") as f:
                        img_data = f.read()
                    contents.append(f"Visual evidence ({path}):")
                    contents.append(
                        types.Part.from_bytes(data=img_data, mime_type="image/png")
                    )
        except Exception as e:
            console.print(f"[yellow][!] Failed to load screenshot: {e}[/yellow]")
    
    console.print("[bold purple][*] Gemini analyzing...[/bold purple]")
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=contents
        )
        return response.text
    except Exception as e:
        console.print(f"[bold red][X] Gemini API Error: {e}[/bold red]")
        return str(e)

def chat_loop(initial_context: str):
    client = get_gemini_client()
    if not client: return
    
    console.print("\n[bold green]=== Interactive Chat Mode ===[/bold green]")
    console.print("[italic]Type 'q', 'quit', or 'exit' to leave.[/italic]\n")
    
    try:
        chat = client.chats.create(model='gemini-2.5-flash')
        system_msg = "You are an expert penetration tester. We are solving a CTF target together."
        chat.send_message(f"{system_msg}\n\nContext:\n{initial_context}")
    except Exception as e:
        console.print(f"[bold red][X] Chat failed to start: {e}[/bold red]")
        return
        
    while True:
        try:
            user_input = console.input("[bold yellow]You >[/bold yellow] ")
            if user_input.strip().lower() in ['q', 'quit', 'exit']:
                break
            
            response = chat.send_message(user_input)
            console.print("\n[bold purple]Agent >[/bold purple]")
            console.print(Markdown(response.text))
            console.print("")
        except (KeyboardInterrupt, EOFError):
            break
        except Exception as e:
            console.print(f"[bold red][X] Error: {e}[/bold red]")
