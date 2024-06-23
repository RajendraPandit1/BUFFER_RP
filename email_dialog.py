from PyQt5.QtWidgets import QDialog, QLabel, QLineEdit, QDialogButtonBox
from PyQt5.QtGui import QIcon
import os

class EmailDialog(QDialog):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Esqueci-me da palavra-passe")
        self.setFixedSize(300, 150)  # Set a fixed size for the dialog
        file_path = os.path.join("Image", "logo.png")
        self.setWindowIcon(QIcon(file_path))
        # Add an email icon
        self.email_label = QLabel(self)
        self.email_label.setGeometry(20, 20, 32, 32)  # Set position and size
        
        # Add input box for email
        self.email_input = QLineEdit(self)
        self.email_input.setPlaceholderText("Introduza o seu e-mail")
        self.email_input.setGeometry(60, 25, 200, 25)  # Set position and size
        
        # Add submit and cancel buttons
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        self.button_box.setGeometry(50, 80, 200, 30)  # Set position and size
        
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
    
    def get_email(self):
        return self.email_input.text()
