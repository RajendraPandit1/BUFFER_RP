import time
import requests
from PyQt5.QtCore import QThread, pyqtSignal

class DirectoryBruteForce(QThread):
    result_changed = pyqtSignal(int, str)

    def __init__(self, url, wordlist):
        super().__init__()
        self.url = url
        self.wordlist = wordlist

    def run(self):
        with open(self.wordlist) as f:
            for line in f:
                directory = line.strip()
                target_url = f"{self.url}/{directory}"
                try:
                    response = requests.get(target_url)
                    self.result_changed.emit(response.status_code, target_url)
                except requests.ConnectionError:
                    self.result_changed.emit(-1, target_url)
                time.sleep(2)  # Wait for 2 seconds between requests
