# This Python file uses the following encoding: utf-8
import sys
from PySide2.QtWidgets import QApplication, QMainWindow,QHeaderView
from PySide2 import QtWidgets
from window import *
from scapy.all import *
from getmac import get_mac_address

class Packet_Error(RuntimeError):
        def __init__(self, msg):
            self.message = msg

class pasoib_8(QMainWindow):
    def __init__(self):
        QMainWindow.__init__(self)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.Interfaces = get_windows_if_list()
        self.Packets = list()

        self.ui.comboBox_interface.addItem('-------------------')
        for item in self.Interfaces:
            tmp = item.get('name')
            self.ui.comboBox_interface.addItem(tmp)

        self.ui.pushButton_choose_int.clicked.connect(self.interface_pressed)
        self.ui.pushButton_create.clicked.connect(self.create_pressed)
        self.ui.pushButton_send.clicked.connect(self.send_pressed)




        self.ui.tableWidget_Queue.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.ui.tableWidget_Queue.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.ui.tableWidget_Queue.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.ui.tableWidget_Queue.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.ui.tableWidget_Queue.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.ui.tableWidget_Queue.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)








    def interface_pressed(self):
        self.Current_Interface = self.ui.comboBox_interface.currentText()
        self.ui.statusbar.showMessage('Interface "' + self.Current_Interface + '" was choosen')

    def send_pressed(self):
        self.ui.statusbar.showMessage('')
        try:
            if self.Packets:
                ethernet = Ether(src = get_mac_address(ip=self.ui.lineEdit_IPSrc.text()), dst = get_mac_address(ip=self.ui.lineEdit_IPDst.text()))
                for i in self.Packets: 
                    sendp(ethernet/i,iface=self.Current_Interface)
                self.Packets.clear()
                self.ui.tableWidget_Queue.setRowCount(0)
                self.ui.statusbar.showMessage('Packets were sent')
            else:
                self.ui.statusbar.showMessage('There is no packets')
        except:
            self.Packets.clear()
            self.ui.tableWidget_Queue.setRowCount(0)
            self.ui.statusbar.showMessage('Failed sending packet')
            if not hasattr(self, 'Current_Interface'):
                self.ui.statusbar.showMessage('Failed sending packet: Interface was not choosen!')



    def create_pressed(self):
        try:
            #Filling IP-level
            #IP Version
            if self.ui.lineEdit_IPVersion.text():
                ip_version = int(self.ui.lineEdit_IPVersion.text())
            else :
                ip_version = 4 #This is default value
            #IHL
            if self.ui.lineEdit_IPIHL.text():
                ip_ihl = int(self.ui.lineEdit_IPIHL.text())
            else :
                ip_ihl = None #This is default value
            #TOS
            if self.ui.lineEdit_IPTOS.text():
                #ip_tos = int(self.ui.lineEdit_IPTOS.text())
                ip_tos = int(self.ui.lineEdit_IPTOS.text(),2)
            else :
                ip_tos = 0b00000000 #This is default value
            #Length
            if self.ui.lineEdit_IPLen.text():
                ip_len = int(self.ui.lineEdit_IPLen.text())
            else :
                ip_len = None #This is default value
            #ID
            if self.ui.lineEdit_IPID.text():
                ip_id = int(self.ui.lineEdit_IPID.text())
            else :
                ip_id = 1 #This is default value
            #Flags
            if self.ui.lineEdit_IPFlags.text():
                ip_flags = int(self.ui.lineEdit_IPFlags.text(),2)
            else :
                ip_flags = 0b000 #This is default value
            #Fragmentation
            if self.ui.lineEdit_IPFrag.text():
                ip_frag = int(self.ui.lineEdit_IPFrag.text())
            else :
                ip_frag = 0 #This is default value
            #TTL
            if self.ui.lineEdit_IPTTL.text():
                ip_ttl = int(self.ui.lineEdit_IPTTL.text())
            else :
                ip_ttl = 64 #This is default value
            #Protocol
            if self.ui.lineEdit_IPProt.text():
                ip_prot = int(self.ui.lineEdit_IPProt.text())
            else :
                ip_prot = 0 #This is default value
            #Checksum
            if self.ui.lineEdit_IPChecksum.text():
                ip_check = int(self.ui.lineEdit_IPChecksum.text())
            else :
                ip_check = None #This is default value
            #IP Source
            if self.ui.lineEdit_IPSrc.text():
                ip_src = self.ui.lineEdit_IPSrc.text()
            else :
                ip_src = None #This is default value
            #IP Destination
            if self.ui.lineEdit_IPDst.text():
                ip_dst = self.ui.lineEdit_IPDst.text()
            else :
                ip_dst = None #This is default value
            #IP Options
            if self.ui.lineEdit_IPOpt.text():
                ip_opt = self.ui.lineEdit_IPOpt.text()
            else :
                ip_opt = [] #This is default value
            #Payload
            if self.ui.plainTextEdit_IPData.toPlainText():
                self.IP_Payload = self.ui.plainTextEdit_IPData.toPlainText()
            #
            packet = IP(
                version = ip_version,
                ihl = ip_ihl,
                tos = ip_tos,
                len = ip_len,
                id = ip_id,
                flags = ip_flags,
                frag = ip_frag,
                ttl = ip_ttl,
                proto = ip_prot,
                chksum = ip_check,
                src = ip_src,
                dst = ip_dst,
                options = ip_opt
            )
            #Adding IP payload
            if hasattr(self, 'IP_Payload'):
                tmp = packet/Raw(load = self.IP_Payload)
                packet = tmp
                del self.IP_Payload


            self.ui.statusbar.showMessage('Packet was created')

            #Filling UDP
            if self.ui.lineEdit_UDPSrc.text():
                try:
                    #Source port
                    if self.ui.lineEdit_UDPSrc.text():
                        udp_sport = int(self.ui.lineEdit_UDPSrc.text())
                    else :
                        udp_sport = 53 #This is default value
                    #Destination Port
                    if self.ui.lineEdit_UDPDst.text():
                        udp_dport = int(self.ui.lineEdit_UDPDst.text())
                    else :
                        udp_dport = 53 #This is default value
                    #Length
                    if self.ui.lineEdit_UDPLen.text():
                        udp_len = int(self.ui.lineEdit_UDPLen.text())
                    else :
                        udp_len = None #This is default value
                    #Checksum
                    if self.ui.lineEdit_UDPChecksum.text():
                        udp_check = int(self.ui.lineEdit_UDPChecksum.text())
                    else :
                        udp_check = None #This is default value
                    #Payload
                    if self.ui.plainTextEdit_UDPData.toPlainText():
                        self.Payload = self.ui.plainTextEdit_UDPData.toPlainText()
                    #
                    udp_packet = UDP(
                        sport = udp_sport,
                        dport = udp_dport,
                        len = udp_len,
                        chksum = udp_check
                    )
                    #Incapsulation
                    if hasattr(self, 'Payload'):
                        res = packet/udp_packet/Raw(load = self.Payload)
                        del self.Payload
                    else :
                        res = packet/udp_packet
                    #
                    self.Packets.append(res)
                    self.ui.statusbar.showMessage('UDP packet was created')
                    self.ui.tableWidget_Queue.insertRow(0)
                    self.ui.tableWidget_Queue.setItem(0, 0, QtWidgets.QTableWidgetItem("UDP"))
                    self.ui.tableWidget_Queue.setItem(0, 3, QtWidgets.QTableWidgetItem((self.ui.lineEdit_UDPSrc.text())))
                    self.ui.tableWidget_Queue.setItem(0, 4, QtWidgets.QTableWidgetItem((self.ui.lineEdit_UDPDst.text())))
                except:
                    self.ui.statusbar.showMessage('Failed creating UDP packet')


            #Filling TCP
            elif self.ui.lineEdit_TCPSrc.text():
                try:
                    #Source port
                    if self.ui.lineEdit_TCPSrc.text():
                        tcp_sport = int(self.ui.lineEdit_TCPSrc.text())
                    else :
                        tcp_sport = 20 #This is default value
                    #Destination Port
                    if self.ui.lineEdit_TCPDst.text():
                        tcp_dport = int(self.ui.lineEdit_TCPDst.text())
                    else :
                        tcp_dport = 80 #This is default value
                    #Sequence number
                    if self.ui.lineEdit_TCPSeq.text():
                        tcp_seq = int(self.ui.lineEdit_TCPSeq.text())
                    else :
                        tcp_seq = 0 #This is default value
                    #Acknowledgment number
                    if self.ui.lineEdit_TCPAck.text():
                        tcp_ack = int(self.ui.lineEdit_TCPAck.text())
                    else :
                        tcp_ack = 0 #This is default value
                    #Data offset
                    if self.ui.lineEdit_TCPDataOffset.text():
                        tcp_dataofs = int(self.ui.lineEdit_TCPDataOffset.text())
                    else :
                        tcp_dataofs = None #This is default value
                    #Reserved
                    if self.ui.lineEdit_TCPReserved.text():
                        tcp_reserved = int(self.ui.lineEdit_TCPReserved.text())
                    else :
                        tcp_reserved = 0 #This is default value
                    #Flags
                    if self.ui.lineEdit_TCPFlags.text():
                        #tcp_flags = map(bin,self.ui.lineEdit_TCPFlags.text())#NOT INT: BINARY STRING
                        tcp_flags = int(self.ui.lineEdit_TCPFlags.text(),2)
                    else :
                        tcp_flags = 0b000000010 #This is default value
                    #Window
                    if self.ui.lineEdit_TCPWindow.text():
                        tcp_window = int(self.ui.lineEdit_TCPWindow.text())
                    else :
                        tcp_window = 8192 #This is default value
                    #Checksum
                    if self.ui.lineEdit_TCPChecksum.text():
                        tcp_check = int(self.ui.lineEdit_TCPChecksum.text())
                    else :
                        tcp_check = None #This is default value
                    #Urgent pointer
                    if self.ui.lineEdit_TCPUrgent.text():
                        tcp_urg = int(self.ui.lineEdit_TCPUrgent.text())
                    else :
                        tcp_urg = 0 #This is default value
                    #Options
                    if self.ui.lineEdit_TCPOptions.text():
                        tcp_options = [(self.ui.lineEdit_TCPOptions.text(),int(self.ui.lineEdit_TCPOptionValue.text()))]
                    else :
                        tcp_options = [] #This is default value
                    #Payload
                    if self.ui.plainTextEdit_TCPData.toPlainText():
                        self.Payload = self.ui.plainTextEdit_TCPData.toPlainText()
                    #
                    tcp_packet = TCP(
                        sport = tcp_sport,
                        dport = tcp_dport,
                        seq = tcp_seq,
                        ack = tcp_ack,
                        dataofs = tcp_dataofs,
                        reserved = tcp_reserved,
                        flags = tcp_flags,
                        window = tcp_window,
                        chksum = tcp_check,
                        urgptr = tcp_urg,
                        options = tcp_options #[('MSS', 536)]
                    )

                    #Incapsulation
                    if hasattr(self, 'Payload'):
                        res = packet/tcp_packet/Raw(load = self.Payload)
                        del self.Payload
                    else :
                        res = packet/tcp_packet
                    #
                    self.Packets.append(res)
                    self.ui.statusbar.showMessage('TCP packet was created')
                    self.ui.tableWidget_Queue.insertRow(0)
                    self.ui.tableWidget_Queue.setItem(0, 0, QtWidgets.QTableWidgetItem("TCP"))
                    self.ui.tableWidget_Queue.setItem(0, 3, QtWidgets.QTableWidgetItem((self.ui.lineEdit_TCPSrc.text())))
                    self.ui.tableWidget_Queue.setItem(0, 4, QtWidgets.QTableWidgetItem((self.ui.lineEdit_TCPDst.text())))
                except:
                    self.ui.statusbar.showMessage('Failed creating TCP packet')

            #Filling ICMP
            elif self.ui.lineEdit_ICMPType.text():
                try:
                    #Filling ICMP packet
                    #Type
                    if self.ui.lineEdit_ICMPType.text():
                        icmp_type = int(self.ui.lineEdit_ICMPType.text())
                    else :
                        icmp_type = 8 #This is default value
                    #Code
                    if self.ui.lineEdit_ICMPCode.text():
                        icmp_code = int(self.ui.lineEdit_ICMPCode.text())
                    else :
                        icmp_code = 0 #This is default value
                    #Checksum
                    if self.ui.lineEdit_ICMPChecksum.text():
                        icmp_check = int(self.ui.lineEdit_ICMPChecksum.text())
                    else :
                        icmp_check = None #This is default value
                    #Identificator
                    if self.ui.lineEdit_ICMPID.text():
                        icmp_id = int(self.ui.lineEdit_ICMPID.text())
                    else :
                        icmp_id = 0 #This is default value
                    #
                    if self.ui.lineEdit_ICMPSeq.text():
                        icmp_seq = int(self.ui.lineEdit_ICMPSeq.text())
                    else :
                        icmp_seq = 0 #This is default value
                    #Payload
                    if self.ui.plainTextEdit_ICMPData.toPlainText():
                        self.Payload = self.ui.plainTextEdit_ICMPData.toPlainText()
                    #
                    icmp_packet = ICMP(
                        type = icmp_type,
                        code = icmp_code,
                        chksum = icmp_check,
                        id = icmp_id,
                        seq = icmp_seq
                    )
                    #Incapsulation
                    if hasattr(self, 'Payload'):
                        res = packet/icmp_packet/Raw(load = self.Payload)
                        del self.Payload
                    else :
                        res = packet/icmp_packet
                    self.Packets.append(res)
                    self.ui.statusbar.showMessage('ICMP packet was created')
                    self.ui.tableWidget_Queue.insertRow(0)
                    self.ui.tableWidget_Queue.setItem(0, 0, QtWidgets.QTableWidgetItem("ICMP"))
                    self.ui.tableWidget_Queue.setItem(0, 5, QtWidgets.QTableWidgetItem((self.ui.lineEdit_ICMPType.text())))
                except:
                    self.ui.statusbar.showMessage('Failed creating ICMP packet')
            else:
                self.Packets.append(packet)
                self.ui.tableWidget_Queue.insertRow(0)
                self.ui.tableWidget_Queue.setItem(0, 0, QtWidgets.QTableWidgetItem("IP"))
            #

            self.ui.tableWidget_Queue.setItem(0, 1, QtWidgets.QTableWidgetItem((self.ui.lineEdit_IPSrc.text())))
            self.ui.tableWidget_Queue.setItem(0, 2, QtWidgets.QTableWidgetItem((self.ui.lineEdit_IPDst.text())))

        except:
            self.ui.statusbar.showMessage('Failed creating packet')





if __name__ == "__main__":
    app = QApplication([])
    window = pasoib_8()
    window.show()
    sys.exit(app.exec_())



