import subprocess
import os
import time


def simulate_suspicious_path():
    temp_dir = os.environ.get("TEMP")
    target = os.path.join(temp_dir, "suspicious_sim.py")

    # Create a simple Python file in Temp
    payload = (
        "import time\n"
        "print('Simulated suspicious process running from TEMP')\n"
        "time.sleep(30)\n"
    )

    with open(target, "w") as f:
        f.write(payload)

    print(f"File created at: {target}")
    print("Running it now – check your monitor!")

    # Run using system Python, not PyCharm venv
    python_path = r"C:\Users\User\AppData\Local\Programs\Python\Python314\python.exe"

    proc = subprocess.Popen([python_path, target])
    print(f"PID: {proc.pid} – monitor should alert within 5 seconds!")

    time.sleep(35)
    proc.terminate()
    os.remove(target)
    print("Simulation finished!")


simulate_suspicious_path()