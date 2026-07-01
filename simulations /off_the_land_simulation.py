import subprocess
import os
import time


def simulate_living_off_the_land():
    print("Starting simulation – Living off the Land...")

    # Use system Python to open powershell :simulating an attacker
    python_path = r"C:\Users\User\AppData\Local\Programs\Python\Python314\python.exe"

    temp_dir = os.environ.get("TEMP")
    target = os.path.join(temp_dir, "lol_sim.py")

    payload = (
        "import subprocess\n"
        "import time\n"
        "print('Simulating attacker using powershell...')\n"
        "proc = subprocess.Popen(['powershell.exe', '-Command', 'Start-Sleep 30'])\n"
        "print(f'powershell.exe PID: {proc.pid}')\n"
        "time.sleep(35)\n"
        "proc.terminate()\n"
    )

    # Save to Desktop instead of Temp
    target = os.path.join(os.path.expanduser("~"), "Desktop", "lol_sim.py")

    with open(target, "w") as f:
        f.write(payload)

    proc = subprocess.Popen([python_path, target])
    print(f"PID: {proc.pid} – monitor should alert now!")

    time.sleep(40)
    proc.terminate()
    os.remove(target)
    print("Simulation finished!")


simulate_living_off_the_land()
