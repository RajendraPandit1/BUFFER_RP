#import the library from qt5
from datetime import datetime   
from email.mime.multipart import MIMEMultipart
import sys
import threading
import webbrowser
from PyQt5.QtWidgets import QMainWindow ,QErrorMessage, QApplication ,QPushButton, QDialog ,QCheckBox,QVBoxLayout, QDialogButtonBox,QHBoxLayout, QLabel, QMessageBox ,QLineEdit ,QTableWidgetItem ,QFileDialog
from PyQt5.QtCore import (Qt, QCoreApplication,QDate,QTimer)
from PyQt5.QtGui import QIcon 
from PyQt5.QtGui import QPixmap

from scapy.all import *
import mysql.connector
import hashlib 
import subprocess
import os
import json
from contextlib import closing
import re
import random
from PyQt5.QtCore import QThread, pyqtSignal
import requests
import string
import smtplib
from email.mime.text import MIMEText

#import the my file on the same folder
from Login_Screen import Ui_Login_Screen
from Dashboard_Screen import Ui_dashboard_screen
from Splash_Screen import Ui_Splash_Screen
from Signup_Screen import Ui_signup_screen
from Login_Screen import Ui_Login_Screen

from email_dialog import EmailDialog
from network_scanner import ScanThread, PortScanThread
from network_sniffer import NetworkSniffer
from sqlmap_runner import SQLMapRunner
from subdomain_enum import SubdomainEnumerator
from directory_brute_force import DirectoryBruteForce

#global variables
count = 0
name_user_ = ""
user_id = 0
email_user_ = ""
#---------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------
#class the dashboard screen to call from the login screen

class dashboard_screen(QMainWindow):
    def __init__(self):
        super().__init__()

        self.scan_thread = None
        self.port_scan_threads = []


        self.sqlmap_runner = SQLMapRunner()
        self.sqlmap_runner.finished.connect(self.handle_output)


        self.ui = Ui_dashboard_screen()
        self.ui.setupUi(self)
        #set the titme and the icon
        self.setWindowTitle("Buffer RP")
        file_path = os.path.join("Image", "logo.png")
        self.setWindowIcon(QIcon(file_path))

        #set the icon and the name bar hidden
        self.ui.icon_text.setHidden(True)
        self.ui.icon_only.setVisible(True)

        self.ui.username.setText(name_user_)
                                     
        #set the dashboard button selected and the show the dashboard screen from the stack widget
        self.ui.stackedWidget.setCurrentIndex(1)

        #dashboard button eveent
        self.ui.dash_1.clicked.connect(self.dashboard_1_clicked)    
        self.ui.dash_2.clicked.connect(self.dashboard_1_clicked)
    
        #host button event
        self.ui.host_1.clicked.connect(self.find_host_clicked)
        self.ui.host_2.clicked.connect(self.find_host_clicked)

        #email button event
        self.ui.email_1.clicked.connect(self.email_clicked)
        self.ui.email_2.clicked.connect(self.email_clicked)

        #packet button event
        self.ui.packet_1.clicked.connect(self.packet_clicked)
        self.ui.packet_2.clicked.connect(self.packet_clicked)

        #hidden information button event
        self.ui.hiden_info_1.clicked.connect(self.hiden_info_clicked)
        self.ui.hiden_info_2.clicked.connect(self.hiden_info_clicked)

        #sql button event
        self.ui.sql_inj.clicked.connect(self.sql_inj_clicked)

        #subdom button event
        self.ui.subdom.clicked.connect(self.subdom_clicked)

        #Directory brute force button event
        self.ui.brute_force.clicked.connect(self.brute_force_clicked)

        #xss button event
        self.ui.xss.clicked.connect(self.xss_clicked)

        #setting button 
        self.ui.setting_1.clicked.connect(self.setting_clicked)
        self.ui.setting_3.clicked.connect(self.setting_clicked)

        #logout button event 
        self.ui.logout_1.clicked.connect(self.logout_clicked)
        self.ui.logout_2.clicked.connect(self.logout_clicked)


        #scan for the email databrease button
        self.ui.button_search_email.clicked.connect(self.button_search_email_clicked)

        #scan the host of the network
        self.ui.button_search_host.clicked.connect(self.button_search_host_clicked)

        #file choose  button event and get metadata
        self.ui.selecionar_ficherio.clicked.connect(self.selecionar_ficherio_clicked)

        #select the packet capture button event
        self.ui.button_packets_capture.clicked.connect(self.button_packets_capture_clicked)

        self.packet_sniffer = None

        #select the button sql injection button event
        self.ui.button_sql_start.clicked.connect(self.run_sqlmap)
        self.ui.button_sql_stop_2.clicked.connect(self.sqlmap_runner.stop_sqlmap)

        #select the subomain search button evett
        self.ui.subdomain_button.clicked.connect(self.start_enumeration)

        #Directory brute force button event
        self.ui.button_dirsearch.clicked.connect(self.brute_force_dir_clicked)
        self.ui.buttton_stop_dirsearch_2.clicked.connect(self.stop_brute_force_clicked)
        
        #xss finder button event 
        self.ui.button_xss_start.clicked.connect(self.check_xss)
        self.ui.button_xss_save.clicked.connect(self.save_results_)


        #password change button event from the setting
        self.ui.button_change_password.clicked.connect(self.change_password)

        #open the video on browser
        self.ui.button_site_encontrar_host_2.clicked.connect(lambda: self.open_site("http://localhost/find_host.php"))
        self.ui.button_site_subdomain.clicked.connect(lambda: self.open_site("http://localhost/subdomain.php"))
        self.ui.button_site_sql.clicked.connect(lambda: self.open_site("http://localhost/sql.php"))
        self.ui.button_site_dir_search.clicked.connect(lambda: self.open_site("http://localhost/dir_search.php"))
        self.ui.button_site_xss.clicked.connect(lambda: self.open_site("http://localhost/xss.php"))
        self.ui.button_site_packet.clicked.connect(lambda: self.open_site("http://localhost/packet.php"))
        self.ui.button_site_email_databreach.clicked.connect(lambda: self.open_site("http://localhost/email_databreach.php"))
        self.ui.button_site_metadata_file.clicked.connect(lambda: self.open_site("http://localhost/metadata_file.php"))
        
        #information stacks
        self.ui.button_info_host.clicked.connect(self.button_info_host_change)
        self.ui.button_info_informacao.clicked.connect(self.button_info_informacao)
        self.ui.button_info_pacotes.clicked.connect(self.button_info_pacotes)
        self.ui.button_info_vulnerabilidades.clicked.connect(self.button_info_vulnerabilidades)
        self.ui.button_info_violacao_email.clicked.connect(self.button_info_violacao_email)

        #button clean finde host
        self.ui.button_find_host_clean.clicked.connect(self.clean_host)
        self.ui.button_search_email_clean.clicked.connect(self.clean_search_email)
        self.ui.button_packets_capture_clean.clicked.connect(self.clean_packets_capture)
        self.ui.selecionar_ficherio_clean.clicked.connect(self.clean_metadata)
        self.ui.subdomain_button_clean.clicked.connect(self.clean_subdomain)
        self.ui.button_sql_clean.clicked.connect(self.sql_clean)
        self.ui.buttton_clean_dirsearch.clicked.connect(self.clean_dirsearch)
        self.ui.button_xss_clean.clicked.connect(self.clean_xss)
        #----------------------------------------------------------------
        
        self.ui.stackedWidget_2.setCurrentIndex(1)

    def button_info_host_change(self):
        self.ui.stackedWidget_2.setCurrentIndex(1)
    def button_info_informacao(self):
        self.ui.stackedWidget_2.setCurrentIndex(4)
    def button_info_pacotes(self):
        self.ui.stackedWidget_2.setCurrentIndex(0)
    def button_info_vulnerabilidades(self):
        self.ui.stackedWidget_2.setCurrentIndex(2)
    def button_info_violacao_email(self):
        self.ui.stackedWidget_2.setCurrentIndex(3)
    

    def open_site(self, url):
        try:
            webbrowser.open(url)
        except Exception as e:
            print(f"Failed to open {url}: {e}")
    
    def clean_host(self):
        self.ui.find_host_table.setRowCount(0)
    def clean_search_email(self):
        self.ui.table_email.setRowCount(0)
    def clean_packets_capture(self):
        self.ui.packet_capture_textarea.setText("")
    def clean_metadata(self):
        self.ui.file_information.setRowCount(0)
    def clean_subdomain(self):
        self.ui.subdomain_table.setRowCount(0)
    def sql_clean(self):
        self.ui.sqlinjection_text.setText("")
    def clean_dirsearch(self):
        self.ui.dirsearch_table.setRowCount(0)
    def clean_xss(self):
        self.ui.tabel_xss.setRowCount(0)
#------------------------------------------------------------------------------------------------------------------------
    def change_password(self):
        old_password = self.ui.password_dash.text()
        new_password = self.ui.new_password_dash.text()
        confirm_password = self.ui.new_das_pass_conf.text()

        #check the new password and the  conform password are same or not 
        if not new_password == confirm_password:
            showMessage_info(self,"Dados inválido","A nova senha não é a mesma no campo de confirmação")
        else:
            #insert the user data into the database
           conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="bufferrp"
            )
           cursor = conn.cursor()
           hashed_password = hashlib.sha256(old_password.encode()).hexdigest()

           #code to comperson of the the password the uder inter to change the password
           cursor.execute("SELECT * FROM users WHERE id = %s AND password = %s",(user_id,hashed_password))
           if cursor.fetchone() is None:
               showMessage_info(self,"Dados inválido","Verificar senha atual ! esta inválido")
           else:
               hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
               cursor.execute("UPDATE users SET password = %s WHERE id = %s",(hashed_password,user_id))
               conn.commit()
               showMessage_info(self,"Sucesso","A senha foi alterada com sucesso")

        try:
            # Connect to the database again to insert the log entry
            with closing(mysql.connector.connect(
                    host="localhost",
                    user="root",
                    password="",
                    database="bufferrp")) as conn2:
                
                with closing(conn2.cursor()) as cursor2:
                    # Add a log entry for user registration
                    cursor2.execute("INSERT INTO user_logs (user_id, action) VALUES (%s, %s)",
                                    (user_id, "utilizador alterou a senha"))
                    conn2.commit()  # Commit to ensure the log is inserted

        except mysql.connector.Error as db_err:
            showMessage(self, "Error", f"Erro de banco de dados ao registrar log: {db_err}")
        except Exception as e:
            showMessage(self, "Error", f"Erro desconhecido ao registrar log: {str(e)}")

               #send to the login screen
        self.close()
        # send to the loging page after change of password
        self.login_screen = login_screen()
        self.login_screen.show()
               

#---------------------------------------------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------------------------------------------------------------
    global stop_requested
    stop_requested = False


    def check_xss(self):
        try:
            # Connect to the database again to insert the log entry
            with closing(mysql.connector.connect(
                    host="localhost",
                    user="root",
                    password="",
                    database="bufferrp")) as conn2:
                
                with closing(conn2.cursor()) as cursor2:
                    # Add a log entry for user registration
                    cursor2.execute("INSERT INTO user_logs (user_id, action) VALUES (%s, %s)",
                                    (user_id, "o utilizador utiliza a ferramenta xss scanner "))
                    conn2.commit()  # Commit to ensure the log is inserted

        except mysql.connector.Error as db_err:
            showMessage(self, "Error", f"Erro de banco de dados ao registrar log: {db_err}")
        except Exception as e:
            showMessage(self, "Error", f"Erro desconhecido ao registrar log: {str(e)}")
        file_path = "xss_payload.txt"
        with open(file_path, 'r', encoding='utf-8') as file:
            payloads = file.readlines()  # Read all lines from the file

        url = self.ui.xss_url.text()
        cookie = self.ui.cookies_xss.text()
        cookie_inputs = cookie.split(";")  # Assuming cookies are separated by ";"
        cookies = {}
        for input_pair in cookie_inputs:
            if "=" in input_pair:
                name, value = input_pair.strip().split("=")
                cookies[name.strip()] = value.strip()

        if not url:
            showMessage_info(self, "Url", "Introduza o url ! esta falta")
        else:
            results = []  # List to store the results
            for line in payloads:
                payload = line.strip()  # Removing any extra whitespace
                if stop_requested:
                    break
                url_with_payload = url.replace('hack', payload)
                try:
                    response = requests.get(url_with_payload, cookies=cookies)
                    html_content = response.text
                    javascript_code = ""
                    script_start = html_content.find("<script>")
                    while script_start != -1:
                        script_end = html_content.find("</script>", script_start)
                        if script_end != -1:
                            script = html_content[script_start:script_end + len("</script>")]
                            javascript_code += script
                        script_start = html_content.find("<script", script_start + 1)

                    if 'alert(1)' in javascript_code:
                        result = "Vulnerável"
                    else:
                        result = "Não vulnerável"
                    results.append((payload, result))
                except requests.RequestException as e:
                    results.append((payload, f"Error: {e}"))

            # Create a table and show results
            self.show_results_table(results)

    def save_results_(self):
        file_path = r"..\Outputs\Xss\results.txt"  # Define the file path to save the results

        try:
            # Check if the file exists
            file_exists = os.path.isfile(file_path)
            
            # Determine the file mode ('w' for write, 'a' for append if the file exists)
            file_mode = 'a' if file_exists else 'w'
            
            # Open the file in the determined mode
            with open(file_path, file_mode, encoding='utf-8') as file:
                # Write the header only if the file is newly created (write mode)
                if not file_exists:
                    file.write("Payload,Result,Timestamp\n")
                
                # Write or append the data
                for row in range(self.ui.tabel_xss.rowCount()):
                    payload_item = self.ui.tabel_xss.item(row, 0)
                    result_item = self.ui.tabel_xss.item(row, 1)
                    if payload_item and result_item:
                        payload = payload_item.text()
                        result = result_item.text()
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        file.write(f"{payload},{result},{timestamp}\n")
            
            if file_exists:
                QMessageBox.information(self, "sucesso", "Resultados anexados com sucesso ao results.txt!")
            else:
                QMessageBox.information(self, "sucesso", "Resultados salvos com sucesso em results.txt!")
        except Exception as e:
            QMessageBox.critical(self, "error", f"Falha ao salvar os resultados: {e}")

    def show_results_table(self, results):
        # Assuming you have a method to display results in a table
        self.ui.tabel_xss.setRowCount(len(results))
        for row, (payload, result) in enumerate(results):
            self.ui.tabel_xss.setItem(row, 1, QTableWidgetItem(payload))
            self.ui.tabel_xss.setItem(row, 0, QTableWidgetItem(result))
#------------------------------------------------------------------------------------------------------------------------------------------------------
    def brute_force_dir_clicked(self):
        try:
            # Connect to the database again to insert the log entry
            with closing(mysql.connector.connect(
                    host="localhost",
                    user="root",
                    password="",
                    database="bufferrp")) as conn2:
                
                with closing(conn2.cursor()) as cursor2:
                    # Add a log entry for user registration
                    cursor2.execute("INSERT INTO user_logs (user_id, action) VALUES (%s, %s)",
                                    (user_id, "utilização do utilizador para encontrar a ferramenta de diretório "))
                    conn2.commit()  # Commit to ensure the log is inserted

        except mysql.connector.Error as db_err:
            showMessage(self, "Error", f"Erro de banco de dados ao registrar log: {db_err}")
        except Exception as e:
            showMessage(self, "Error", f"Erro desconhecido ao registrar log: {str(e)}")
        url = self.ui.dirsearch_url.text()
        # If the url is empty, show the error message
        if not url:
            showMessage_info(self,"Url","Introduza o url ! esta falta")
        else:
            self.ui.dirsearch_table.setRowCount(0)
            wordlist = "wordlist.txt"  # the name of the wordlist file
            self.worker = DirectoryBruteForce(url, wordlist)
            self.worker.result_changed.connect(self.update_table)
            self.worker.start()

            # Disable the start button and enable the stop button
            self.ui.button_dirsearch.setEnabled(False)
            self.ui.buttton_stop_dirsearch_2.setEnabled(True)

    def stop_brute_force_clicked(self):
        # Stop the worker thread
        if self.worker:
            self.worker.terminate()  # Terminate the worker thread
            # Enable the start button and disable the stop button
            self.ui.button_dirsearch.setEnabled(True)
            self.ui.buttton_stop_dirsearch_2.setEnabled(False)
            
    def update_table(self, status_code, url):
        row_position = self.ui.dirsearch_table.rowCount()
        self.ui.dirsearch_table.insertRow(row_position)
        self.ui.dirsearch_table.setItem(row_position, 0, QTableWidgetItem(str(status_code)))
        self.ui.dirsearch_table.setItem(row_position, 1, QTableWidgetItem(url))


 #---------------------------------------------------------------------------------------------------------------------------------------------------------

    def start_enumeration(self):
        try:
            # Connect to the database again to insert the log entry
            with closing(mysql.connector.connect(
                    host="localhost",
                    user="root",
                    password="",
                    database="bufferrp")) as conn2:
                
                with closing(conn2.cursor()) as cursor2:
                    # Add a log entry for user registration
                    cursor2.execute("INSERT INTO user_logs (user_id, action) VALUES (%s, %s)",
                                    (user_id, "utilizador utiliza ferramenta de subdomínio"))
                    conn2.commit()  # Commit to ensure the log is inserted

        except mysql.connector.Error as db_err:
            showMessage(self, "Error", f"Erro de banco de dados ao registrar log: {db_err}")
        except Exception as e:
            showMessage(self, "Error", f"Erro desconhecido ao registrar log: {str(e)}")
    
        domain =self.ui.domain_field.text()
        if domain:
            self.ui.subdomain_button.setEnabled(False)  # Disable button during enumeration
            self.subdomain_thread = threading.Thread(target=self.enumerate_subdomains, args=(domain,))
            self.subdomain_thread.start()

    def enumerate_subdomains(self, domain):
        enumerator = SubdomainEnumerator(domain)
        subdomains = enumerator.enumerate_subdomains()

        # Update the table with the results
        self.ui.subdomain_table.setRowCount(len(subdomains))
        for i, subdomain in enumerate(subdomains):
            self.ui.subdomain_table.setItem(i, 0, QTableWidgetItem(subdomain))

        self.ui.subdomain_button.setEnabled(True)  # Enable button after enumeration

        
 #---------------------------------------------------------------------------------------------------------------------------------------------------------

    def run_sqlmap(self):
        try:
            # Connect to the database again to insert the log entry
            with closing(mysql.connector.connect(
                    host="localhost",
                    user="root",
                    password="",
                    database="bufferrp")) as conn2:
                
                with closing(conn2.cursor()) as cursor2:
                    # Add a log entry for user registration
                    cursor2.execute("INSERT INTO user_logs (user_id, action) VALUES (%s, %s)",
                                    (user_id, "o utilizador utiliza a ferramenta sqlmap "))
                    conn2.commit()  # Commit to ensure the log is inserted

        except mysql.connector.Error as db_err:
            showMessage(self, "Error", f"Erro de banco de dados ao registrar log: {db_err}")
        except Exception as e:
            showMessage(self, "Error", f"Erro desconhecido ao registrar log: {str(e)}")
        url = self.ui.url_sql.text()
        cookies = self.ui.cookies_sql.text()
        other = self.ui.other_option_sql.text()

        self.sqlmap_runner.start_sqlmap(url, cookies, other)
        self.ui.sqlinjection_text.clear()


    def stop_sqlmap(self):
        # Run stop_sqlmap in a separate thread to avoid blocking the GUI
        threading.Thread(target=self.sqlmap_runner.stop_sqlmap).start()

    def handle_output(self, output):
        self.ui.sqlinjection_text.append(output)

    def closeEvent(self, event):
        self.stop_sqlmap()
        event.accept()


    def button_packets_capture_clicked(self):
        # set the logs
        try:
            # Connect to the database again to insert the log entry
            with closing(mysql.connector.connect(
                    host="localhost",
                    user="root",
                    password="",
                    database="bufferrp")) as conn2:
                
                with closing(conn2.cursor()) as cursor2:
                    # Add a log entry for user registration
                    cursor2.execute("INSERT INTO user_logs (user_id, action) VALUES (%s, %s)",
                                    (user_id, "utilizador uso ferramenta de captura de pacotes"))
                    conn2.commit()  # Commit to ensure the log is inserted

        except mysql.connector.Error as db_err:
            showMessage(self, "Error", f"Erro de banco de dados ao registrar log: {db_err}")
        except Exception as e:
            showMessage(self, "Error", f"Erro desconhecido ao registrar log: {str(e)}")
        # Create a new instance of NetworkSniffer if not already created
        if self.packet_sniffer is None:
            self.packet_sniffer = NetworkSniffer()
            self.packet_sniffer.packet_received.connect(self.display_packet_info)

        # Clear the packet capture text area
        self.ui.packet_capture_textarea.clear()

        if self.packet_sniffer.isRunning():
            # If packet sniffer is already running, stop it
            self.stop_capture()
        else:
            # Start packet capture
            self.start_capture()

    def start_capture(self):
        # Change button text to "Stop" and connect it to stop_capture method
        self.ui.button_packets_capture.setText("Parar")
        self.ui.button_packets_capture.clicked.disconnect(self.button_packets_capture_clicked)
        self.ui.button_packets_capture.clicked.connect(self.stop_capture)

        # Set stop_sniffing flag to False and start packet sniffer
        self.packet_sniffer.stop_sniffing = False
        self.packet_sniffer.start()

    def stop_capture(self):
        # Change button text to "Start" and connect it to button_packets_capture_clicked method
        self.ui.button_packets_capture.setText("Começar")
        self.ui.button_packets_capture.clicked.disconnect(self.stop_capture)
        self.ui.button_packets_capture.clicked.connect(self.button_packets_capture_clicked)

        # Set stop_sniffing flag to True to stop packet sniffer
        self.packet_sniffer.stop_sniffing = True

    def display_packet_info(self, packet_info):
        # Format packet information and append to the packet capture text area
        display_text = "Packet Information:\n"
        for key, value in packet_info.items():
            if value is not None:
                display_text += f"{key}: {value}\n"
        display_text += "=" * 100 + "\n"
        self.ui.packet_capture_textarea.append(display_text)
 #---------------------------------------------------------------------------------------------------------------------------------------------------------

    def selecionar_ficherio_clicked(self):
        try:
            # Connect to the database again to insert the log entry
            with closing(mysql.connector.connect(
                    host="localhost",
                    user="root",
                    password="",
                    database="bufferrp")) as conn2:
                
                with closing(conn2.cursor()) as cursor2:
                    # Add a log entry for user registration
                    cursor2.execute("INSERT INTO user_logs (user_id, action) VALUES (%s, %s)",
                                    (user_id, "utilizador a ferramenta meta data de ficherio"))
                    conn2.commit()  # Commit to ensure the log is inserted

        except mysql.connector.Error as db_err:
            showMessage(self, "Error", f"Erro de banco de dados ao registrar log: {db_err}")
        except Exception as e:
            showMessage(self, "Error", f"Erro desconhecido ao registrar log: {str(e)}")
        options = QFileDialog.Options()
        file_filter = (
            "All Files (*.*);;"
            "Word Documents (*.docx);;"
            "PowerPoint Presentations (*.pptx);;"
            "MP3 Files (*.mp3);;"
            "PDF Files (*.pdf);;"
            "Text Files (*.txt);;"
            "Image Files (*.jpg;*.jpeg;*.png)"
        )
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File", "", file_filter, options=options)
        
        if file_path:
            self.ui.caminho.setText(f"{file_path}")
            metadata = self.get_file_metadata(file_path)
            self.display_metadata(metadata)
        else:
            self.ui.caminho.setText("Nenhum ficheiro selecionado.")


    def get_file_metadata(self, file_path):
        metadata = {}
        try:
            # Use exiftool to get metadata
            result = subprocess.run(
                ['exiftool', '-j', file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if result.returncode != 0:
                metadata['Error'] = result.stderr
            else:
                file_metadata = json.loads(result.stdout)[0]
                metadata.update(file_metadata)

        except Exception as e:
            metadata['Error'] = str(e)

        return metadata
    
    def display_metadata(self, metadata):
        self.ui.file_information.setRowCount(len(metadata))

        row = 0
        for key, value in metadata.items():
            self.ui.file_information.setItem(row, 0, QTableWidgetItem(key))
            self.ui.file_information.setItem(row, 1, QTableWidgetItem(str(value)))
            row += 1

     

 #---------------------------------------------------------------------------------------------------------------------------------------------------------

    def button_search_host_clicked(self):   
        ip = self.ui.ipaddress_search.text()
        cidr = self.ui.cidr_ip_search.text()
        ip_range = f"{ip}/{cidr}"

                # set the logs
        try:
            # Connect to the database again to insert the log entry
            with closing(mysql.connector.connect(
                    host="localhost",
                    user="root",
                    password="",
                    database="bufferrp")) as conn2:
                
                with closing(conn2.cursor()) as cursor2:
                    # Add a log entry for user registration
                    cursor2.execute("INSERT INTO user_logs (user_id, action) VALUES (%s, %s)",
                                    (user_id, "Encontrar host :"+ip_range))
                    conn2.commit()  # Commit to ensure the log is inserted

        except mysql.connector.Error as db_err:
            showMessage(self, "Error", f"Erro de banco de dados ao registrar log: {db_err}")
        except Exception as e:
            showMessage(self, "Error", f"Erro desconhecido ao registrar log: {str(e)}")

        self.ui.find_host_table.setRowCount(0)

        #disable the search button
        self.ui.button_search_host.setEnabled(False)

        # Define the update_table function
        def update_table(hosts_up):
            self.ui.find_host_table.setRowCount(len(hosts_up))
            self.ui.button_search_host.setEnabled(True)

            for row_number, host in enumerate(hosts_up):
                self.ui.find_host_table.setItem(row_number, 0, QTableWidgetItem(host['mac']))
                self.ui.find_host_table.setItem(row_number, 1, QTableWidgetItem(host['ip']))

                # Define the update_ports function
                def update_ports(open_ports, row=row_number):
                    open_ports_str = ', '.join(map(str, open_ports)) if open_ports else "N/A"
                    self.ui.find_host_table.setItem(row, 2, QTableWidgetItem(open_ports_str))

                # Create and start the port scan thread
                port_scan_thread = PortScanThread(host['ip'], row_number)  # Pass the row_number argument
                port_scan_thread.finished.connect(update_ports)
                self.port_scan_threads.append(port_scan_thread)
                port_scan_thread.start()

        # Create and start the scan thread
        self.scan_thread = ScanThread(ip_range)
        self.scan_thread.finished.connect(update_table)
        self.scan_thread.start()

 #---------------------------------------------------------------------------------------------------------
    def button_search_email_clicked(self):
        email = self.ui.email_search.text()
                # set the logs
        try:
            # Connect to the database again to insert the log entry
            with closing(mysql.connector.connect(
                    host="localhost",
                    user="root",
                    password="",
                    database="bufferrp")) as conn2:
                
                with closing(conn2.cursor()) as cursor2:
                    # Add a log entry for user registration
                    cursor2.execute("INSERT INTO user_logs (user_id, action) VALUES (%s, %s)",
                                    (user_id, "Violação do email"+email))
                    conn2.commit()  # Commit to ensure the log is inserted

        except mysql.connector.Error as db_err:
            showMessage(self, "Error", f"Erro de banco de dados ao registrar log: {db_err}")
        except Exception as e:
            showMessage(self, "Error", f"Erro desconhecido ao registrar log: {str(e)}")

        #disable the search button
        self.ui.button_search_email.setEnabled(False)

        # Set the row count
        value = 0

        api_key = "1bf94ff907f68d511de9a610a6ff9263"

        def search_email(api_key, email):
            url = "https://leak-lookup.com/api/search"

            # Define the parameters for the POST request
            payload = {
                'key': api_key,
                'type': 'email_address',
                'query': email
            }

            try:
                self.ui.table_email.setRowCount(0)
                response = requests.post(url, data=payload)
                if response.status_code == 200:
                    data = response.json()
                    if data['error'] == "true":
                        print(f"Error: {data['message']}")
                    else:
                        if not data['message']:
                            showMessage_info(self,"Informação","O e-mail não contém nenhuma violação de banco de dados")
                            #clean the table email
                            self.ui.button_search_email.setEnabled(True)
                            self.ui.table_email.setRowCount(0)
                        else:
                            value = 1
                            #sete the data of today's data
                            today_date = datetime.today().strftime("%Y-%m-%d")

                            for breach_site, records in data['message'].items():
                                self.ui.table_email.setRowCount(len(data['message']))
                                self.ui.table_email.setItem(value - 1, 0, QTableWidgetItem(breach_site))
                                self.ui.table_email.setItem(value - 1, 1, QTableWidgetItem(today_date))
                                self.ui.table_email.setItem(value - 1, 2, QTableWidgetItem(f"Encontrado na violação de dados {breach_site}"))
                                value += 1
                        
                            self.ui.button_search_email.setEnabled(True)

            except Exception as e:
                showMessage_code(self,"Erro",str(e))

        if not email:
            showMessage_info(self,"Informação","Insira um e-mail")
            self.ui.button_search_email.setEnabled(True)
            
        else:
            search_email(api_key, email)

#---------------------------------------------------------------------------------------------------------
       

    def dashboard_1_clicked(self):
        self.ui.stackedWidget.setCurrentIndex(1)

    def find_host_clicked(self):
        self.ui.stackedWidget.setCurrentIndex(2)
    
    def email_clicked(self):
        self.ui.stackedWidget.setCurrentIndex(9)

    def packet_clicked(self):
        self.ui.stackedWidget.setCurrentIndex(8)

    def hiden_info_clicked(self):
        self.ui.stackedWidget.setCurrentIndex(0)

    def sql_inj_clicked(self):
        self.ui.stackedWidget.setCurrentIndex(4)

    def subdom_clicked(self):
        self.ui.stackedWidget.setCurrentIndex(3)

    def brute_force_clicked(self):
        self.ui.stackedWidget.setCurrentIndex(5)


    def xss_clicked(self):
        self.ui.stackedWidget.setCurrentIndex(6)

    def setting_clicked(self):
        self.ui.stackedWidget.setCurrentIndex(10)
        self.ui.dash_name.setText(name_user_)
        self.ui.dash_email.setText(email_user_)

    def logout_clicked(self):
        #send to the login screen 

        # set the logs
        try:
            # Connect to the database again to insert the log entry
            with closing(mysql.connector.connect(
                    host="localhost",
                    user="root",
                    password="",
                    database="bufferrp")) as conn2:
                
                with closing(conn2.cursor()) as cursor2:
                    # Add a log entry for user registration
                    cursor2.execute("INSERT INTO user_logs (user_id, action) VALUES (%s, %s)",
                                    (user_id, "utilizador saiu da sessão"))
                    conn2.commit()  # Commit to ensure the log is inserted

        except mysql.connector.Error as db_err:
            showMessage(self, "Error", f"Erro de banco de dados ao registrar log: {db_err}")
        except Exception as e:
            showMessage(self, "Error", f"Erro desconhecido ao registrar log: {str(e)}")

        self.close()
           #open the login screen
        self.login_screen = login_screen()
        self.login_screen.show()

    

    
#---------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------

def forget_password_update(self,email_user,password_hash):


    # Function to send verification email
    sender_email = 'example@example.com'  #dont forget add email
    receiver_email = email_user
    subject = 'Palavra-passe temporária'
    
    message = MIMEMultipart()
    message['From'] = "Buffer RP"
    message['To'] = receiver_email
    message['Subject'] = subject

       # CSS styles
    css_styles = """
    <style>
        /* Your CSS styles here */
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #333;
            color: #fff;
            padding: 30px;
            border-radius: 10px;
        }
        h1 {
            color: #ff4444;
            margin-bottom: 20px;
        }
        p {
            margin-bottom: 20px;
        }
        .verification-code {
            background-color: #ff4444;
            padding: 10px;
            border-radius: 5px;
            font-size: 20px;
            text-align: center;
            margin-top: 20px;
            margin-bottom: 40px;
        }
        .footer {
            text-align: center;
            color: #ccc;
            font-size: 12px;
        }
    </style>
    """

     # Add HTML content to the message
    body = """
    <!DOCTYPE html>
    <html lang="pt-PT">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Palavra-passe temporária</title>
        {}
    </head>
    <body>
        <div class="container">
            <h1>Palavra-passe temporária</h1>
            <p>É temporário! Utilize a seguinte palavra-passe para iniciar sessão na sua conta. Não se esqueça de alterar a sua palavra-passe posteriormente:</p>
            <div class="Palavra-Passe">{}</div>
            <div class="footer">
                Este email foi enviado pela Buffer RP. &copy; 2024. Todos os direitos reservados.
            </div>
        </div>
    </body>
    </html>
    """.format(css_styles, password_hash)
    message.attach(MIMEText(body, 'html'))


    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, 'password here')  # dont forget to change password
            server.sendmail(sender_email, receiver_email, message.as_string())
            showMessage_info(self,"Palavra-passe temporária","O email já enviado com sucesso")

    except Exception as e:
            print("Error sending email:", e)




#---------------------------------------------------------------------------------------------------------
def verification_code_create(self,email_user,username_user,password_user):

    # Function to generate a random verification code
    def generate_verification_code(length=6):
     return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
    
    # Function to send verification email
    sender_email = 'example@example.com'
    receiver_email = email_user
    subject = 'Verificação de e-mail'
    verification_code = generate_verification_code()
    
    message = MIMEMultipart()
    message['From'] = "Buffer RP"
    message['To'] = receiver_email
    message['Subject'] = subject

       # CSS styles
    css_styles = """
    <style>
        /* Your CSS styles here */
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #333;
            color: #fff;
            padding: 30px;
            border-radius: 10px;
        }
        h1 {
            color: #ff4444;
            margin-bottom: 20px;
        }
        p {
            margin-bottom: 20px;
        }
        .verification-code {
            background-color: #ff4444;
            padding: 10px;
            border-radius: 5px;
            font-size: 20px;
            text-align: center;
            margin-top: 20px;
            margin-bottom: 40px;
        }
        .footer {
            text-align: center;
            color: #ccc;
            font-size: 12px;
        }
    </style>
    """

     # Add HTML content to the message
    body = """
    <!DOCTYPE html>
    <html lang="pt-PT">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verificação de Email</title>
        {}
    </head>
    <body>
        <div class="container">
            <h1>Verificação de Email</h1>
            <p>Obrigado por se inscrever! Utilize o código de verificação seguinte para verificar o seu endereço de email:</p>
            <div class="verification-code">{}</div>
            <p>Se não solicitou esta verificação, pode ignorar este email com segurança.</p>
            <p>Se tiver alguma dúvida ou precisar de assistência, entre em contacto com a nossa equipa de suporte.</p>
            <div class="footer">
                Este email foi enviado pela Buffer RP. &copy; 2024. Todos os direitos reservados.
            </div>
        </div>
    </body>
    </html>
    """.format(css_styles, verification_code)
    message.attach(MIMEText(body, 'html'))


    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, 'password here') # write a password
            server.sendmail(sender_email, receiver_email, message.as_string())
            showMessage_info(self,"Email de veficação","O email já enviado com sucesso")
            #sent to the message box to verify the verification code
            showMessage_code(self,verification_code,email_user,username_user,password_user)


    except Exception as e:
            print("Error sending email:", e)
    
#---------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------
#message box with icon and title
def showMessage(self, title,message):
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Critical)
    msg.setWindowTitle(title)
    msg.setText(message)
    file_path = os.path.join("Image", "logo.png")
    msg.setWindowIcon(QIcon(file_path))
    msg.setStandardButtons(QMessageBox.Ok)
    msg.exec_()  


def showMessage_info(self, title,message):
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Information)
    msg.setWindowTitle(title)
    msg.setText(message)
    file_path = os.path.join("Image", "logo.png")
    msg.setWindowIcon(QIcon(file_path))
    msg.setStandardButtons(QMessageBox.Ok)
    msg.exec_()  

def showMessage_code(self,verification_code,email_user,username_user,password_user):
    msgBox = QMessageBox()
    msgBox.setWindowTitle("Entre o código")
    msgBox.setText("Código de verificação:")
    file_path = os.path.join("Image", "logo.png")
    msgBox.setWindowIcon(QIcon(file_path))
    msgBox.setStandardButtons(QMessageBox.Ok)

    # Add a line edit widget for entering the verification code
    line_edit = QLineEdit()
    msgBox.layout().addWidget(line_edit, 1, 1, 1, 1)

    # Show the message box
    ret = msgBox.exec_()

    # If "OK" button is clicked
    if ret == QMessageBox.Ok:
        # Get the entered verification code
        entered_code = line_edit.text().strip()

        # Validate the entered code
        if entered_code == verification_code:
           

           ################################################################
           #insert the user data into the database
           conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="bufferrp"
            )
           cursor = conn.cursor()
           hashed_password = hashlib.sha256(password_user.encode()).hexdigest()
           cursor.execute("INSERT INTO users (username,email,password) VALUES (%s,%s,%s)",(username_user,email_user,hashed_password))
           conn.commit()    

           #close the signup screen
           self.close()
           #open the login screen
           self.login_screen = login_screen()
           self.login_screen.show()

        try:
            # Connect to the database again to insert the log entry
            with closing(mysql.connector.connect(
                    host="localhost",
                    user="root",
                    password="",
                    database="bufferrp")) as conn2:
                
                with closing(conn2.cursor()) as cursor2:
                    # Add a log entry for user registration
                    cursor2.execute("SELECT id FROM users WHERE email = %s", (email_user,))
                    result = cursor2.fetchone()
                    user_id_ = result[0]

                    cursor2.execute("INSERT INTO user_logs (user_id, action) VALUES (%s, %s)",
                                    (user_id_, "Utilizador registado"))
                    conn2.commit()  # Commit to ensure the log is inserted

                showMessage_info(self, "Sucesso", "Registo bem-sucedido")

        except mysql.connector.Error as db_err:
            showMessage(self, "Error", f"Erro de banco de dados ao registrar log: {db_err}")
        except Exception as e:
            showMessage(self, "Error", f"Erro desconhecido ao registrar log: {str(e)}")
#---------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------
#create the class of the signup screen to call from the login screen
class signup_screen(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_signup_screen()
        self.ui.setupUi(self)
        self.ui.login.clicked.connect(self.back_to_login)
        self.ui.signup_button.clicked.connect(self.signup)
        self.ui.show_password.stateChanged.connect(self.show_password)
        
    #show the password
    def show_password(self):
        if self.ui.show_password.isChecked():
            self.ui.password.setEchoMode(QLineEdit.Normal)
        else:
            self.ui.password.setEchoMode(QLineEdit.Password)


    #BUTTON EVENT
    def back_to_login(self):
        #close the signup screen
        self.close()
        #open the login screen
        self.login_screen = login_screen()
        self.login_screen.show()

    def signup(self):
        username = self.ui.username.text()
        email = self.ui.email.text()
        password = self.ui.password.text()

        def contains_number(input_string):
            return bool(re.search(r'\d', input_string))
        
        #check the username email and password is not empty and check the username contains numbers
        if username == ""or email == "" or password == "":
                #show the message box saying that fill the required fields.
                showMessage(self,"error","Por favor, introduza o seu nome de utilizador, email e senha.")
        else: 
            if contains_number(username):
                showMessage(self,"error","O nome de utilizador não pode ter números.")
            else:
                try:
                    conn = mysql.connector.connect(
                    host="localhost",
                    user="root",
                    password="",
                    database="bufferrp")

                    hashed_password = hashlib.sha256(password.encode()).hexdigest()
                    cursor = conn.cursor()

                     # Check if the username or email already exists
                    query = "SELECT * FROM users WHERE username = %s OR email = %s"
                    cursor.execute(query, (username, email))
                    existing_user = cursor.fetchone()

                    if existing_user:
                        showMessage_info(self,"Informação","Utilizador já existem.")
                    else:
                        verification_code_create(self,email,username,password)


                except Exception as e:
                    print(e)

#---------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------


#create the class for the login screen to call from the splash screen
class login_screen(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.ui = Ui_Login_Screen()
        self.ui.setupUi(self)
        self.ui.login_button.clicked.connect(self.login)
        self.ui.signup.clicked.connect(self.signup)

        #---------------------------------------------------------------------------------------------------------#
        self.ui.button_forgot.clicked.connect(self.button_forgot)
        #---------------------------------------------------------------------------------------------------------#
        #when the user click on the check box then the password will be shown
        self.ui.show_password.stateChanged.connect(self.show_password)
    
    #button forget 
    def button_forgot(self):
         # Create and show the custom email dialog
        dialog = EmailDialog()
        if dialog.exec_() == QDialog.Accepted:
            email = dialog.get_email()
            if not email:
                QMessageBox.information(self, 'Campo de e-mail', f'Preenche o campo de e-mail')
            else:
                #check on the database there is  any account with that email
                try:
                    with closing(mysql.connector.connect(
                            host="localhost",
                            user="root",
                            password="",
                            database="bufferrp")) as conn:
                        with closing(conn.cursor()) as cursor:
                            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
                            result = cursor.fetchone()
                            if not result:
                                QMessageBox.information(self, 'Campo de e-mail', f'Não existe nenhum utilizador com esse e-mail')
                            else:
                                #if user exit then create a random password and update in database and send to user email

                                # Generate a random password
                                password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))
                                #encrypt the password and update to the database
                                hashed_password = hashlib.sha256(password.encode()).hexdigest()
                                cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
                                conn.commit()

                                # Send the email
                                forget_password_update(self,email,password)

                #except Exception
                except mysql.connector.Error as db_err:
                    showMessage(self, "Error", f"Erro de banco de dados ao registrar log: {db_err}")
                except Exception as e:
                    showMessage(self, "Error", f"Erro desconhecido ao registrar log: {str(e)}")
                                




#------------------------------------------------------------------------------------------------------------------------#
#------------------------------------------------------------------------------------------------------------------------#
#------------------------------------------------------------------------------------------------------------------------#

    #show the password
    def show_password(self):
        if self.ui.show_password.isChecked():
            self.ui.password.setEchoMode(QLineEdit.Normal)
        else:
            self.ui.password.setEchoMode(QLineEdit.Password)

    #BUTTON EVENT
    def login(self):
       #need to validate the user name and password are empty or not by using the if statement
       user_name = self.ui.username.text()
       password = self.ui.password.text()
       #if the user name and password are empty then show the error message
       if user_name == "" or password == "":
           #if the user name and password are empty show an error message
            showMessage(self,"error","Por favor, insira seu nome de utilizador e senha.")
       else:
           #sql connection fo  validate the user name and password try exception
            try:
                    # Securely connect to the database
                    with closing(mysql.connector.connect(
                            host="localhost",
                            user="root",
                            password="",
                            database="bufferrp")) as conn:

                        # Hash the password using SHA-256
                        hashed_password = hashlib.sha256(password.encode()).hexdigest()

                        # Create a cursor object
                        with closing(conn.cursor()) as cursor:
                            # Define the query to search for the user
                            query = "SELECT * FROM users WHERE (username = %s OR email = %s) AND password = %s"
                            cursor.execute(query, (user_name, user_name, hashed_password))

                            # Fetch the result
                            result = cursor.fetchone()

                            if result:
                                global name_user_
                                name_user_ = result[1]
                                global user_id
                                user_id = result[0]
                                global email_user_
                                email_user_ = result[2]    

                                     # Add the logs saying that the user logged in
                                try:
                                    log_query = "INSERT INTO user_logs (user_id, action) VALUES (%s, %s)"
                                    cursor.execute(log_query, (user_id, "Utilizador com sessão iniciada"))
                                    conn.commit()
                                except mysql.connector.Error as log_err:
                                    showMessage(self, "Informação", f"Erro : {log_err}")

                                # Close the login screen
                                self.close()
                                # Open the dashboard screen
                                self.dashboard_screen = dashboard_screen()
                                self.dashboard_screen.show()
                                

                            else:
                                showMessage_info(self, "Informação", "Nome de utilizador ou senha incorretos.")

            except mysql.connector.Error as db_err:
                    showMessage(self, "Informação", f"Erro de banco de dados c001: {db_err}")
            except Exception as e:
                    showMessage(self, "Informação", "Nome de utilizador ou senha incorretos ou erro desconhecido."+str(e))
##---------------------------------------------------------------------------------------------------------------------------------------------------------#    
##---------------------------------------------------------------------------------------------------------------------------------------------------------#    
##---------------------------------------------------------------------------------------------------------------------------------------------------------#    

    #BUTTON EVENT
    def signup(self):
        #close the login screen
        self.close()
        #open the signup screen
        self.signup_screen = signup_screen()
        self.signup_screen.show()
       
#---------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------

#create the class for the splash screen
class splash_screen(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Splash_Screen()
        self.ui.setupUi(self)

        #Remove  the title bar from the splash screen
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)

        #qtimer start
        self.timer = QTimer()
        self.timer.timeout.connect(self.progress)
        self.timer.start(25)
        #show the splash screen
        self.show()
        
    def progress(self):
     global count
     #set value to the progress bar
     self.ui.progressBar.setValue(count)

    #close tht splash screen after 100 and topent the login screen
     if count > 100:
        self.timer.stop()
        self.close()

        #load the login screen
        self.login_screen = login_screen()
        self.login_screen.show()

     count += 1

#---------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------

if __name__ == '__main__':
    app = QApplication(sys.argv)
    windows = splash_screen()
    sys.exit(app.exec_())

#---------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------