import subprocess
import time
import os


def simulate_suspicious_child():
    print("Starting simulation – opening cmd.exe as child process...")

    temp_dir = os.environ.get("TEMP")
    target = os.path.join(temp_dir, "child_sim.py")

    # Write the payload that opens cmd.exe as child
    payload = (
        "import subprocess\n"
        "import time\n"
        "print('Opening cmd.exe as child...')\n"
        "proc = subprocess.Popen(['cmd.exe', '/c', 'ping -n 30 127.0.0.1 > nul'])\n"
        "print(f'cmd.exe PID: {proc.pid}')\n"
        "time.sleep(35)\n"
        "proc.terminate()\n"
    )

    with open(target, "w") as f:
        f.write(payload)

    python_path = r"C:\Users\User\AppData\Local\Programs\Python\Python314\python.exe"
    proc = subprocess.Popen([python_path, target])
    print(f"PID: {proc.pid} – monitor should alert now!")

    time.sleep(40)
    proc.terminate()
    os.remove(target)
    print("Simulation finished!")


simulate_suspicious_child()