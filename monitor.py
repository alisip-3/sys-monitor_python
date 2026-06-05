import psutil
import time
from datetime import datetime

# processes we trust checked by exact path
TRUSTED_PROCESSES = {
    'msedge.exe': r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    'svchost.exe': r'C:\Windows\System32\svchost.exe',
    'explorer.exe': r'C:\Windows\explorer.exe',
    'system': None,  # always PID 4
}

CHROME_VALID_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

# who is allowed to open who
TRUSTED_PARENTS = {
    'svchost.exe':    ['services.exe'],
    'explorer.exe':   ['userinit.exe'],
    'cmd.exe':        ['explorer.exe', 'powershell.exe'],
    'msmpeng.exe':    ['services.exe'],
    'powershell.exe': ['explorer.exe', 'pycharm64.exe'],
}

SUSPICIOUS_CHILDREN = ['cmd.exe', 'powershell.exe', 'wscript.exe']
SUSPICIOUS_PATHS = ['\\downloads\\', '\\appdata\\local\\temp\\', '\\users\\public\\']


def has_suspicious_parent(proc):
    name = proc.name().lower()
    if name not in TRUSTED_PARENTS:
        return False
    try:
        parent = proc.parent()
        if parent is None:
            return False
        parent_name = parent.name().lower()
        return parent_name not in TRUSTED_PARENTS[name]
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


def is_trusted_process(name, exe, pid):
    name_lower = name.lower() if name else ""
    exe_lower = exe.lower() if exe else ""

    if name_lower == 'system' and pid == 4:
        return True

    if name_lower not in TRUSTED_PROCESSES:
        return False

    expected_path = TRUSTED_PROCESSES[name_lower]
    if expected_path is None:
        return False

    # if path doesn't match possible impersonation
    return exe_lower == expected_path.lower()


def is_suspicious_cmdline(proc):
    # check if python is running a script from a suspicious location
    try:
        cmdline = proc.cmdline()
        cmdline_str = ' '.join(cmdline).lower()
        return any(susp_path in cmdline_str for susp_path in SUSPICIOUS_PATHS)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


print("--- Monitor started successfully ---")
print("-" * 50)

while True:
    processes_list = []

    # psutil needs two calls to calculate cpu - first call initializes it
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    time.sleep(1)

    for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'exe']):
        try:
            cpu = proc.cpu_percent(interval=None)
            proc_info = {
                'pid':    proc.info['pid'],
                'name':   proc.info['name'],
                'cpu':    cpu,
                'memory': proc.info['memory_percent'],
                'exe':    proc.info['exe'],
                'object': proc
            }
            processes_list.append(proc_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    for p in processes_list:

        name = p['name'].lower() if p['name'] else ""
        exe  = p['exe'] if p['exe'] else ""

        if is_trusted_process(p['name'], p['exe'], p['pid']):
            continue

        try:
            cmdline_str = ' '.join(p['object'].cmdline()).lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            cmdline_str = ""

        if 'pycharm' in name or 'pycharm' in exe.lower() or 'pycharm' in cmdline_str or p['pid'] == 0 or 'msedgewebview2' in name:
            continue

        is_fake_chrome = name == 'chrome.exe' and exe != CHROME_VALID_PATH if name else False

        has_suspicious_child = False
        suspicious_child_name = ""
        try:
            for child in p['object'].children():
                if child.name().lower() in SUSPICIOUS_CHILDREN:
                    has_suspicious_child = True
                    suspicious_child_name = child.name()
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        is_running_from_suspicious_path = False
        if exe:
            if any(susp_path in exe.lower() for susp_path in SUSPICIOUS_PATHS):
                is_running_from_suspicious_path = True

        is_suspicious_cmdline_flag = is_suspicious_cmdline(p['object'])
        is_suspicious_parent = has_suspicious_parent(p['object'])

        if is_fake_chrome or has_suspicious_child or is_running_from_suspicious_path or is_suspicious_parent or is_suspicious_cmdline_flag:

            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_line = (
                f"[{current_time}] WARNING: Process '{p['name']}' (PID: {p['pid']}) flagged. "
                f"Fake Chrome: {is_fake_chrome}, "
                f"Suspicious Child: {has_suspicious_child}, "
                f"Suspicious Path: {is_running_from_suspicious_path}, "
                f"Suspicious Parent: {is_suspicious_parent}, "
                f"Suspicious Cmdline: {is_suspicious_cmdline_flag}\n"
            )

            with open("alerts.log", "a", encoding="utf-8") as log_file:
                log_file.write(log_line)

            reasons = []
            if is_fake_chrome:
                reasons.append("impersonating Chrome")
            if has_suspicious_child:
                reasons.append(f"opened suspicious child process: {suspicious_child_name}")
            if is_running_from_suspicious_path:
                reasons.append("running from suspicious path")
            if is_suspicious_cmdline_flag:
                reasons.append("script running from suspicious path")
            if is_suspicious_parent:
                reasons.append("suspicious parent process")

            print(f"!!! ALERT: '{p['name']}' (PID: {p['pid']}) – {', '.join(reasons)} !!!")

    time.sleep(3)
