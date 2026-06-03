import os
import sys
import time
import threading
import subprocess
import webbrowser

# Ensure we can import the sniffer module
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import sniffer
from colorama import Fore, Style, init

init(autoreset=True)

def fake_type_command(prompt, command, speed=0.07):
    """Simulates realistic typing of a terminal command."""
    sys.stdout.write(prompt)
    sys.stdout.flush()
    time.sleep(1)
    for char in command:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(speed)
    time.sleep(0.5)
    sys.stdout.write("\n")
    sys.stdout.flush()

def hacker_simulation():
    """Opens a browser and performs actual physical attacks against the local server."""
    # Wait for sniffer to start and user to prepare
    time.sleep(4)
    
    # Attack 1: Cleartext Credentials
    url1 = "http://127.0.0.1/?username=admin&password=MySecretPassword123"
    webbrowser.open(url1)
    time.sleep(6) # Let the user see the browser and the sniffer react
    
    # Attack 2: SQL Injection
    url2 = "http://127.0.0.1/?id=1' OR 1=1 --"
    webbrowser.open(url2)
    time.sleep(6)
    
    # Attack 3: Path Traversal
    url3 = "http://127.0.0.1/?file=../../../../Windows/System32/drivers/etc/hosts"
    webbrowser.open(url3)
    time.sleep(6)
    
def main():
    # Clear screen for a clean, fake terminal experience
    os.system("cls" if os.name == "nt" else "clear")
    
    # Fake PowerShell prompt
    prompt = f"PS C:\\Users\\Office\\CodeAlpha\\AegisFlow> "
    command = 'python sniffer.py -i "\\Device\\NPF_Loopback" --payload'
    
    # Simulate typing the command
    fake_type_command(prompt, command)
    
    # Start Local Web Server silently in background
    httpd = subprocess.Popen([sys.executable, "-m", "http.server", "80"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    
    # Initialize the real AegisFlow Sniffer
    parser = sniffer.build_parser()
    args = parser.parse_args(["-i", "\\Device\\NPF_Loopback", "--payload", "--save-json", "--save-pcap"])
    net_sniffer = sniffer.NetworkSniffer(args)
    
    # Run the background visual browser simulation
    sim_thread = threading.Thread(target=hacker_simulation, daemon=True)
    sim_thread.start()
    
    # Stop condition
    def stopper():
        time.sleep(25) # Total duration
        with sniffer.Display._lock:
            sys.stdout.write("^C")
            sys.stdout.flush()
        net_sniffer._running = False
        httpd.terminate()
        
    threading.Thread(target=stopper, daemon=True).start()
    
    # Start the actual sniffer (blocks until _running is False)
    net_sniffer.start()

if __name__ == "__main__":
    # Request Admin Privileges Automatically if not admin
    try:
        is_admin = (os.geteuid() == 0)
    except AttributeError:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        
    if not is_admin:
        import ctypes
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(f'"{a}"' for a in sys.argv), None, 1)
        sys.exit(0)

    main()
