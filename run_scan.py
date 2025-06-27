#!/usr/bin/env python3

# --------------------------------------------------------------------------- #
# BlueAura Scan Launcher - run_scan.py                                        #
# --------------------------------------------------------------------------- #
# This script acts as an intelligent wrapper for blueaura-scanner.py.         #
# It provides two key features:                                               #
# 1. Automatic Stealth Configuration: It forces the scan to run in a "low   #
#    and slow" mode to better evade Web Application Firewalls (WAFs).         #
# 2. WAF/Block Detection: It actively monitors the scan's output for        #
#    excessive timeout errors. If it suspects the scanner has been blocked,   #
#    it terminates the scan and generates a detailed incident report.         #
# --------------------------------------------------------------------------- #

# --------------------------- [ LICENSE & WARNING ] ------------------------- #
# MIT License
#
# Copyright (c) 2024 Your Name
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of a aSoftware.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# -------------------- [!
# --- IMPORTANT LEGAL & ETHICAL WARNING --- !] --------------------
# This tool is intended for educational purposes and for authorized security  #
# testing ONLY.                                                               #
#                                                                             #
# Running this tool against any system without explicit, written permission   #
# from the system's owner is illegal in most jurisdictions and can result in  #
# severe civil and criminal penalties.                                        #
#                                                                             #
# The user of this software assumes all liability for its use. The authors    #
# and contributors are not responsible for any misuse or damage caused by     #
# this program. ALWAYS GET PERMISSION.                                        #
# --------------------------------------------------------------------------- #

import subprocess
import os
import sys
import time
from datetime import datetime
import argparse
import yaml
import requests
import textwrap

# --- Configuration for WAF Detection ---
# If more than TIMEOUT_THRESHOLD errors occur within TIME_WINDOW_SECONDS,
# we assume the scanner has been blocked.
TIMEOUT_THRESHOLD = 20
TIME_WINDOW_SECONDS = 120

def print_startup_warnings():
    """Prints critical warnings to the user on startup."""
    print("="*60)
    print("                BlueAura Scan Launcher")
    print("="*60)
    print("\n[!] --- IMPORTANT LEGAL & ETHICAL WARNING --- [!]")
    warning_text = """
This tool is intended for educational purposes and for authorized security testing ONLY. Running this tool against any system without explicit, written permission from the system's owner is illegal and can result in severe penalties. The user assumes all liability.
"""
    print(textwrap.dedent(warning_text))
    print("Proceeding in 5 seconds...")
    time.sleep(5)

def get_public_ip():
    """Fetches the public IP of the machine running the script."""
    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=10)
        response.raise_for_status()
        return response.json().get('ip', 'Unknown')
    except requests.RequestException:
        return "Could not determine IP"

def generate_incident_report(target_url, error_logs):
    """Generates a detailed HTML report when a WAF block is detected."""
    print("[!] WAF/Block detected! Generating incident report...")
    
    report_name = f"incident_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.html"
    source_ip = get_public_ip()
    
    # Take a sample of the last 15 errors for the report
    error_sample = "\n".join(error_logs[-15:])
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>BlueAura Scanner - Incident Report</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; background-color: #f8f9fa; color: #343a40; }}
            .container {{ max-width: 960px; margin: 20px auto; padding: 20px; background-color: #ffffff; border: 1px solid #dee2e6; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
            h1, h2, h3 {{ color: #004085; border-bottom: 2px solid #b8daff; padding-bottom: 10px; }}
            h1 {{ font-size: 2.5em; text-align: center; }}
            .summary {{ background-color: #fff3cd; border: 1px solid #ffeeba; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
            .metadata-table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
            .metadata-table th, .metadata-table td {{ text-align: left; padding: 12px; border: 1px solid #dee2e6; }}
            .metadata-table th {{ background-color: #e9ecef; width: 30%; }}
            .log-box {{ background-color: #212529; color: #f8f9fa; padding: 15px; border-radius: 5px; font-family: "Courier New", Courier, monospace; white-space: pre-wrap; word-wrap: break-word; max-height: 400px; overflow-y: auto; }}
            .footer {{ text-align: center; margin-top: 20px; font-size: 0.9em; color: #6c757d; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>BlueAura Scanner - Incident Report</h1>

            <div class="summary">
                <h2>Incident Summary</h2>
                <p>The scan was automatically terminated because it was likely detected and blocked by a security system, such as a Web Application Firewall (WAF).</p>
            </div>

            <h2>Incident Details</h2>
            <table class="metadata-table">
                <tr><th>Incident Time (UTC)</th><td>{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
                <tr><th>Target URL</th><td>{target_url}</td></tr>
                <tr><th>Source IP Address</th><td>{source_ip}</td></tr>
                <tr><th>Suspected Cause</th><td>Excessive timeout errors, indicating active blocking of scan traffic.</td></tr>
                <tr><th>Detection Threshold</th><td>{TIMEOUT_THRESHOLD} timeout errors within {TIME_WINDOW_SECONDS} seconds.</td></tr>
            </table>

            <h3>Recommendations</h3>
            <p>The target's security systems are actively preventing the scan. To continue, consider the following:</p>
            <ul>
                <li>Further decrease the scan rate in <code>config.yml</code> (e.g., `rate_limit_per_sec: 0.5`).</li>
                <li>Increase the request timeout further (e.g., `scan_timeout_per_url: 60`).</li>
                <li>If you have permission, request that your IP address (`{source_ip}`) be whitelisted by the site owner.</li>
                <li>Focus the scan on fewer modules to reduce noise.</li>
            </ul>

            <h3>Evidence: Sample Error Logs</h3>
            <p>The following are the last few error messages received before the scan was terminated:</p>
            <div class="log-box"><code>{error_sample}</code></div>
            
            <div class="footer">
                <p>Report generated by BlueAura Scan Launcher</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    with open(report_name, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"[+] Incident report saved as: {report_name}")

def main():
    """Main function to launch and monitor the scanner."""
    parser = argparse.ArgumentParser(
        description="BlueAura Scan Launcher: Runs the main scanner with stealth and WAF detection.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--config", required=True, help="Path to your primary config YAML file (e.g., config.yml).")
    parser.add_argument("--payloads", required=True, help="Path to your payloads YAML file (e.g., payloads.yml).")
    args = parser.parse_args()

    print_startup_warnings()

    # --- Enforce Stealth Configuration ---
    try:
        with open(args.config, 'r') as f:
            config_data = yaml.safe_load(f)
        
        target_url = config_data.get('config', {}).get('target_url', 'Unknown')
        
        # Modify config in memory for stealth
        config_data['config']['rate_limit_per_sec'] = 1
        config_data['config']['scan_timeout_per_url'] = 45
        
        temp_config_path = "temp_stealth_config.yml"
        with open(temp_config_path, 'w') as f:
            yaml.dump(config_data, f)
            
        print("[+] Stealth mode enabled: Rate limit set to 1 req/sec, timeout to 45s.")

    except Exception as e:
        print(f"[!] Error processing config file: {e}")
        sys.exit(1)

    # --- Launch and Monitor the Scanner ---
    command = [
        "python3", "blueaura-scanner.py",
        "--config", temp_config_path,
        "--payloads", args.payloads
    ]
    
    error_timestamps = []
    error_logs = []

    try:
        print("\n[+] Starting BlueAura Scanner process...")
        print("    To run this in the background, first start 'screen -S scanner',")
        print("    then run this command inside the screen session.\n")
        
        # Start the scanner as a subprocess
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

        # Monitor the output in real-time
        for line in iter(process.stdout.readline, ''):
            sys.stdout.write(line) # Print the scanner's output live
            
            # Check for timeout errors
            if "after exception: TimeoutError" in line:
                current_time = time.time()
                error_timestamps.append(current_time)
                error_logs.append(line.strip())
                
                # Keep the list of timestamps within the last TIME_WINDOW_SECONDS
                error_timestamps = [t for t in error_timestamps if current_time - t <= TIME_WINDOW_SECONDS]
                
                # Check if the threshold has been breached
                if len(error_timestamps) >= TIMEOUT_THRESHOLD:
                    generate_incident_report(target_url, error_logs)
                    process.terminate() # Stop the scanner process
                    break # Exit the monitoring loop

        process.stdout.close()
        return_code = process.wait()
        
        if return_code == 0:
            print("\n[+] Scan completed successfully.")
        elif return_code is not None:
             print(f"\n[!] Scan process exited with code {return_code}.")

    except FileNotFoundError:
        print("\n[!] Error: 'blueaura-scanner.py' not found in the current directory.")
        print("    Please ensure both scripts are in the same folder.")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred in the launcher: {e}")
    finally:
        # Clean up the temporary config file
        if os.path.exists(temp_config_path):
            os.remove(temp_config_path)
        print("[+] Cleanup complete.")

if __name__ == "__main__":
    main()
