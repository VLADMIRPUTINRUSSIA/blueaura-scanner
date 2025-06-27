# **BlueAura Scanner**

### **Aura: An Asynchronous URL Risk Analyzer.**

**UPDATE** `2025-06-27T17:53:18Z` UTC `2025-06-27T19:53:48+02:00` CEST

An intelligent, asynchronous security scanner powered by Python and Playwright. It is designed for authorized, defensive (Blue Team) security audits of modern web applications.

Key Features
Intelligent Launcher (run_scan.py): The primary script for running scans. It automates best practices for stealth and error handling.

Automatic Stealth Mode: The launcher forces the scan to run in a "low and slow" mode (1 request/sec, 45s timeout) to help evade detection by Web Application Firewalls (WAFs).

WAF/Block Detection: Actively monitors the scan for signs of being blocked. If detected, it stops the scan and generates a detailed HTML incident report explaining what happened.

Modular Core Scanner (blueaura-scanner.py): The engine of the tool, capable of testing for SQLi, XSS, IDOR, SSRF, missing security headers, open redirects, and more.

Fully Configurable: All scan parameters and payloads are controlled via simple config.yml and payloads.yml files.

Installation
1. Clone the Repository

git clone [https://github.com/VLADMIRPUTINRUSSIA/blueaura-scanner.git](https://github.com/VLADMIRPUTINRUSSIA/blueaura-scanner.git)

cd blueaura-scanner

2. Install Python Libraries
This command reads the requirements.txt file and automatically installs all necessary Python packages.

pip install -r requirements.txt

3. Install Playwright Browsers (Crucial Step)
This command downloads the browser programs (like Chrome) that Playwright needs to run. The --with-deps flag also installs necessary operating system dependencies on Linux.

python3 -m playwright install --with-deps

How to Use the Scanner
It is highly recommended to use the run_scan.py launcher for all scans.

Step 1: Configure Your Target

Open the config.yml file.

Change the target_url to the website you have permission to test.

Enable or disable modules as needed. Note: The launcher will automatically override the speed and timeout settings for stealth.

Step 2: Run the Scan Launcher

Execute the run_scan.py script from your terminal:

python3 run_scan.py --config config.yml --payloads payloads.yml

The launcher will display warnings, apply stealth settings, and then start the main scanner process. You will see the live output from the scanner in your terminal.

Running Long Scans (The Professional Way)
Scanning large websites can take several hours. If you run a long scan in a normal terminal (like Google Cloud Shell), it will be terminated if you close the tab or lose your internet connection.

The correct way to run a long scan is by using a terminal multiplexer like screen. This creates a persistent session on the server that keeps running in the background, even if you disconnect.

Tutorial: Using screen for Persistent Scans
Step 1: Start a screen Session
From your blueaura-scanner directory, start a new session and give it a memorable name.

screen -S scanner

Your terminal will clear, and you will now be inside the persistent screen session.

Step 2: Run the Launcher Inside screen
Start the launcher as you normally would. The scan is now running inside the protected session.

python3 run_scan.py --config config.yml --payloads payloads.yml

Step 3: Detach and Leave the Scan Running
You can now safely "detach" from the session without stopping the scan. Press this key combination:
Ctrl+A, then release, then press D.

You will see a [detached] message. The scan is now running in the background, and you can close your terminal or shut down your computer.

How to Check Progress and Get Results
Step 1: Check if the Scan is Still Running
At any time, you can list your active sessions to see if the scanner is still working:

screen -ls

If you see a session named scanner, it's still running.

Step 2: Reconnect to the Live Session
To jump back into the session and see the live log output, use this command:

screen -r scanner

You will be reconnected to your scan exactly where you left off. (To detach again, use Ctrl+A then D).

Step 3: Know When the Results are Ready
The scan is finished when the script completes. You'll know because:

The screen session will no longer appear when you run screen -ls.

The final HTML report file (e.g., scan_report_example.com.html) will be present in your directory. Check for it with ls -l.

If the scan was blocked by a WAF, an incident_report_...html will be generated instead.

**Disclaimer: This tool is intended for educational purposes and for authorized security testing only. Do not use it on any system without explicit, written permission from the system's owner. The user assumes all liability.**
**The only legitimate reasons to use this tool are for learning or for testing the security of a system you have been given permission to test. It is not for casual use, snooping, or any other activity.**
## **Disclaimer and Limitation of Liability**
This tool is intended for educational purposes and for authorized security testing only.

Intended Use
By using this software, you acknowledge that you are using it exclusively for educational purposes or for security testing on systems for which you have received explicit, written permission from the system's owner. Any other use is strictly prohibited.

No Warranties
THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.

Assumption of Liability & Indemnification
THE USER ASSUMES ALL LIABILITY. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This includes, but is not limited to, direct, indirect, incidental, special, exemplary, or consequential damages (including loss of use, data, or profits; or business interruption).

You agree to indemnify and hold harmless the authors from and against any and all claims and expenses, including attorneys' fees, arising out of your use of this software, including but not limited to your violation of any law or regulation or your violation of these terms.



