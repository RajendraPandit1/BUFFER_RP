import subprocess
import threading
import urllib.parse
from PyQt5.QtCore import QObject, pyqtSignal

class SQLMapRunner(QObject):
    finished = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.process = None
        self.thread = None
        self.stop_event = threading.Event()

    def run_sqlmap(self, url, cookies, other):
        # Encode URL and cookies
        encoded_url = urllib.parse.quote(url, safe=':/?=&')
        encoded_cookies = urllib.parse.quote(cookies, safe=':;=')

        # Construct command
        cmd_command = f'python sqlmap\\sqlmap.py -u "{encoded_url}" --cookie "{encoded_cookies}" {other} --output-dir ..\\Outputs\\Sqlmap  --random-agent '

        # Execute command and capture output
        self.process = subprocess.Popen(cmd_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True)

        # Read and emit output line by line
        for line in self.process.stdout:
            self.finished.emit(line)
            if self.stop_event.is_set():
                break

        # Wait for the subprocess to finish if not stopped
        if not self.stop_event.is_set():
            self.process.wait()

        # Emit signal to indicate completion
        self.finished.emit("Process completed.")
        
        self.process = None

    def start_sqlmap(self, url, cookies, other):
        # Reset stop event before starting
        self.stop_event.clear()

        # Create a new thread to run SQLMap
        self.thread = threading.Thread(target=self.run_sqlmap, args=(url, cookies, other))
        self.thread.start()

    def stop_sqlmap(self):
        # Set the stop event to signal the subprocess to stop
        self.stop_event.set()

        # Terminate the SQLMap subprocess if it's running
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait()  # Ensure the process has terminated

        # Ensure the thread has terminated
        if self.thread and self.thread.is_alive():
            self.thread.join()
        self.thread = None
