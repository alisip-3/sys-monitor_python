import subprocess
import os
import time
import shutil


def simulate_fake_chrome():
    temp_dir = os.environ.get("TEMP")

    # Copy python.exe and rename it to chrome.exe
    python_path = r"C:\Users\User\AppData\Local\Programs\Python\Python314\python.exe"
    fake_chrome = os.path.join(temp_dir, "chrome.exe")

    shutil.copy(python_path, fake_chrome)

    print(f"Fake chrome.exe created at: {fake_chrome}")
    print("Running it – monitor should alert now!")

    proc = subprocess.Popen([fake_chrome])
    print(f"PID: {proc.pid}")

    time.sleep(35)
    proc.terminate()
    os.remove(fake_chrome)
    print("Simulation finished!")


simulate_fake_chrome()
