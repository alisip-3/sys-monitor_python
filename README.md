# Resource Monitor - Context-Based Intrusion Detection

A Python tool that monitors running processes on a Windows machine and alerts when something looks suspicious. Built as a learning project while studying cybersecurity.

The idea behind it is not just to look at CPU usage or process names, but to understand the **context** of each process - where it's running from, who opened it, and what it's doing.

---

## How it works

The monitor runs in the background and checks every process on the machine. For each process it runs a few checks:

- Is a process pretending to be Chrome but running from the wrong folder?
- Did a process open cmd.exe or powershell.exe unexpectedly?
- Is something running from a suspicious location like Temp or Downloads?
- Was a process opened by a parent it shouldn't have?

If any of these checks trigger, the monitor logs the alert to `alerts.log` and prints it to the screen with a clear reason.

---

## How to run

Install the only dependency:
```
pip install psutil
```

Then run the monitor:
```
python monitor.py
```

Keep it running in the background. Alerts will appear in the terminal and get saved to `alerts.log`.

---

## Simulations

There are 4 simulation scripts you can run to test the monitor. Run each one in a separate terminal while the monitor is running.

**simulation_suspicious_path.py**
Creates a Python file inside the Temp folder and runs it from there. The monitor should detect that a script is running from a suspicious location.

**simulation_child.py**
Opens cmd.exe as a child process from an unexpected parent. This simulates what attackers often do after gaining access to a machine.

**simulation_fake_chrome.py**
Copies a Python executable, renames it chrome.exe, and runs it from the Temp folder. The monitor detects that the path doesn't match the real Chrome installation.

**simulation_living_off_the_land.py**
Opens powershell.exe from an untrusted parent process. This simulates a common attacker technique where built-in Windows tools are used to avoid detection.

---

## Project structure

```
monitor.py                          - main monitor
simulation_suspicious_path.py       - simulation 1
simulation_child.py                 - simulation 2
simulation_fake_chrome.py           - simulation 3
simulation_living_off_the_land.py   - simulation 4
```

---

## Notes

- Built and tested on Windows 11
- Requires Python 3.10+
- alerts.log is not included in the repo
