from PyQt5.QtCore import QObject, QThread, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QCheckBox, QPlainTextEdit, QFileDialog, QSplitter, QWidget
from scapy.all import *
from scapy.all import IP
from datetime import datetime
import threading
import sqlite3
import pickle
import os
os.environ["XDG_RUNTIME_DIR"] = "/tmp/runtime-myuser"

class StopFlag:
    def __init__(self):
        self.flag = False

    def set(self):
        self.flag = True

    def clear(self):
        self.flag = False

    def is_set(self):
        return self.flag


class PacketCaptureThread(QObject):
    add_packet_signal = pyqtSignal(object)

    def __init__(self, stop_capture, protocol_checkboxes):
        super().__init__()
        self.stop_capture = stop_capture
        self.protocol_checkboxes = protocol_checkboxes

    def run(self):
        filter_strs = [protocol for checkbox, protocol in self.protocol_checkboxes if checkbox.isChecked()]
        filter_str = " or ".join(filter_strs)

        sniff(filter=filter_str, prn=lambda packet: self.add_packet_signal.emit(packet), stop_filter=lambda p: self.stop_capture.is_set())


class PacketAnalyzer(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Analyzer")
        self.layout = QVBoxLayout()
        self.setup_ui()

        self.stop_capture = threading.Event()
        self.packets = []
        self.all_packets = [] 
        self.conn = sqlite3.connect('packets.db')
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets(
                source_ip TEXT,
                dest_ip TEXT,
                protocol TEXT,
                timestamp TEXT,
                time TEXT,
                info TEXT
            )
        ''')
        self.conn.commit()

    def __del__(self):
        self.conn.close()

    def setup_ui(self):
        self.status_label = QLabel("Status: Idle")
        self.status_label.setStyleSheet('color: red')  # Cor do status enquanto nao procura
        self.layout.addWidget(self.status_label)

        self.splitter = QSplitter()
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels(["Source IP", "Destination IP", "Protocol", "Timestamp", "Time", "Info"])
        self.packet_table.cellClicked.connect(self.show_packet_detail)
        self.splitter.addWidget(self.packet_table)

        self.packet_detail_view = QPlainTextEdit()
        self.packet_detail_view.setReadOnly(True)
        self.splitter.addWidget(self.packet_detail_view)

        self.layout.addWidget(self.splitter)

        self.protocol_checkboxes = [
            (QCheckBox("TCP"), "tcp"),
            (QCheckBox("UDP"), "udp"),
            (QCheckBox("ICMP"), "icmp"),
            (QCheckBox("DNS"), "dns")
        ]

        protocol_layout = QHBoxLayout()

        for checkbox, _ in self.protocol_checkboxes:
            protocol_layout.addWidget(checkbox)

        protocol_widget = QWidget()
        protocol_widget.setLayout(protocol_layout)
        self.layout.addWidget(protocol_widget)

        self.start_button = QPushButton("Start Capture")
        self.start_button.clicked.connect(self.start_capture)
        self.layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Capture")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_capture_func)
        self.layout.addWidget(self.stop_button)

        self.save_button = QPushButton("Save Capture")
        self.save_button.clicked.connect(self.save_capture)
        self.layout.addWidget(self.save_button)

        self.load_button = QPushButton("Load Capture")
        self.load_button.clicked.connect(self.load_capture)
        self.layout.addWidget(self.load_button)

        self.setLayout(self.layout)

    def start_capture(self):
        self.packet_table.clearContents()
        self.packet_table.setRowCount(0)
        self.status_label.setText("Status: Capturing")
        self.status_label.setStyleSheet('color: green')  # Cor do statues em verde enquanto captura
        self.start_button.setEnabled(False)
        for checkbox, _ in self.protocol_checkboxes:
            checkbox.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.packets.clear()
        self.stop_capture.clear()

        self.thread = QThread()
        self.worker = PacketCaptureThread(self.stop_capture, self.protocol_checkboxes)
        self.worker.add_packet_signal.connect(self.process_packet)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.thread.start()

    def stop_capture_func(self):
        self.stop_capture.set()
        self.status_label.setText("Status: Idle")
        self.status_label.setStyleSheet('color: red')  # Cor do status em vermelho enquanto nao caputra
        self.start_button.setEnabled(True)
        for checkbox, _ in self.protocol_checkboxes:
            checkbox.setEnabled(True)
        self.stop_capture.set()
        self.thread.quit()  # Parar a QThread
        self.thread.wait()
        

    def process_packet(self, packet):
        try:
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
            protocol = packet.sprintf("%IP.proto%")
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            time = packet.time
            info = packet.summary()

            packet_data = (source_ip, dest_ip, protocol, timestamp, time, info, packet) 

            row_count = self.packet_table.rowCount()
            self.packet_table.insertRow(row_count)

            source_item = QTableWidgetItem(source_ip)
            dest_item = QTableWidgetItem(dest_ip)
            protocol_item = QTableWidgetItem(protocol)
            timestamp_item = QTableWidgetItem(timestamp)
            time_item = QTableWidgetItem(str(time))
            info_item = QTableWidgetItem(info)

            color_dict = {"tcp": QColor(255, 200, 200), "udp": QColor(200, 255, 200), "icmp": QColor(200, 200, 255), "http": QColor(255, 255, 200), "dns": QColor(255, 255, 255)}
            color = color_dict.get(protocol.lower(), QColor(255, 255, 255))
            for item in [source_item, dest_item, protocol_item, timestamp_item, time_item, info_item]:
                item.setBackground(color)

            self.packet_table.setItem(row_count, 0, source_item)
            self.packet_table.setItem(row_count, 1, dest_item)
            self.packet_table.setItem(row_count, 2, protocol_item)
            self.packet_table.setItem(row_count, 3, timestamp_item)
            self.packet_table.setItem(row_count, 4, time_item)
            self.packet_table.setItem(row_count, 5, info_item)

            self.packets.append(packet_data)
            self.all_packets.append(packet)

            if len(self.packets) % 100 == 0:  # quando tiver coletado outros 100 pacotes
                self.cursor.executemany("INSERT INTO packets VALUES (?, ?, ?, ?, ?, ?)", [(packet[0], packet[1], packet[2], packet[3], str(packet[4]), packet[5]) for packet in self.packets])
                self.conn.commit()
                self.packets.clear()  # Apagar o buffer

        except IndexError:
            pass

        if len(self.packets) >= 100:  # quando tiver coletado 100 pacotes
            self.cursor.executemany("INSERT INTO packets VALUES (?, ?, ?, ?, ?, ?)", [(packet[0], packet[1], packet[2], packet[3], str(packet[4]), packet[5]) for packet in self.packets])
            self.conn.commit()
            self.packets.clear()

    def show_packet_detail(self, row, column):
        if row < len(self.all_packets):  
            packet = self.all_packets[row]
            if isinstance(packet, Packet):
                self.packet_detail_view.setPlainText(packet.show(dump=True))
            else:
                self.packet_detail_view.setPlainText("The selected packet is not a valid Packet object.")
        else:
            self.packet_detail_view.setPlainText("No packet selected.")

    def save_capture(self):
        filename, _ = QFileDialog.getSaveFileName(self, 'Save Capture', '.', 'Packet Capture (*.pcap)')
        if filename:
            wrpcap(filename, self.all_packets)  #ficheiro pcap

    def load_capture(self):
        filename, _ = QFileDialog.getOpenFileName(self, 'Load Capture', '.', 'Packet Capture (*.pcap)')
        if filename:
            self.packet_table.clearContents()
            self.packet_table.setRowCount(0)
            self.packets.clear()

            packets = rdpcap(filename)
            for packet in packets:
                # Processa cada pacote separadamente
                self.process_packet(packet)


            #for packet in self.packets:
            #    self.process_packet(packet)

if __name__ == "__main__":
    app = QApplication([])
    window = PacketAnalyzer()
    window.show()
    app.exec_()
