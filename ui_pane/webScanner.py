import multiprocessing
import sys
import threading
import time
from ftplib import FTP
from multiprocessing import Queue
import nmap
import shodan
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMainWindow, QApplication, QPushButton, QMessageBox, QListWidgetItem, QDialog
from scapy.layers.inet import IP, ICMP, TCP
from scapy.sendrecv import sr1, sr

from resources.UI.welcome_ui import Ui_MainWindow
from scan.host_scan import arp_request, ping_one, syn_443, ack_80
from scan.port_scan import syn_one, fin_one, null_one, xmas_one, udp_one
from scan.settings import Settings
from utensil.tools import CheckIpAddress, get_host_ip, CheckPort


class WelcomePane(QMainWindow):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.__ui = Ui_MainWindow()
        self.__ui.setupUi(self)

        self.setAttribute(Qt.WA_DeleteOnClose)
        self.setCentralWidget(self.__ui.tabWidget)
        self.close_btn = QPushButton("退出程序")
        self.__ui.tabWidget.setCornerWidget(self.close_btn)
        self.close_btn.clicked.connect(self.exit_webScanner)
        self.close_btn.setStyleSheet("QPushButton{\n"
                                     "height:80px; width:80px;"
                                     "background-color: rgb(23, 23, 23);\n"
                                     "color: white;\n"
                                     "}\n"
                                     "QPushButton:hover{\n"
                                     "color: rgb(255, 121, 0);\n"
                                     "}")
        self.__ui.hostAdd_lnEd.setAttribute(QtCore.Qt.WA_MacShowFocusRect, 0)
        self.__ui.PortAdd_lnEd.setAttribute(QtCore.Qt.WA_MacShowFocusRect, 0)
        self.__ui.ServiceAdd_lnEd.setAttribute(QtCore.Qt.WA_MacShowFocusRect, 0)
        self.__ui.PortScan_startPort_lnEd.setAttribute(QtCore.Qt.WA_MacShowFocusRect, 0)
        self.__ui.PortScan_endPort_lnEd.setAttribute(QtCore.Qt.WA_MacShowFocusRect, 0)
        self.__ui.OSAdd_lnEd.setAttribute(QtCore.Qt.WA_MacShowFocusRect, 0)
        self.__ui.selfIp_lab.setText(get_host_ip())

        self.__FlagEditable = (Qt.ItemIsSelectable | Qt.ItemIsUserCheckable
                               | Qt.ItemIsEnabled | Qt.ItemIsEditable)

        self.__ui.ftp_ip_list.drop_release.connect(self.ftp_ip_list_drop_release)
        self.__ui.ftp_userName_list.drop_release.connect(self.ftp_username_list_drop_release)
        self.__ui.ftp_password_list.drop_release.connect(self.ftp_password_list_drop_release)

        self.ftp_ip_list = []
        self.ftp_username_list = []
        self.ftp_password_list = []

        self.os_active_port = []
        self.os_inactive_port = []
        self.os_windows_rate = 0
        self.os_linux_rate = 0
        self.os_is_linux = []

    def refresh_ip(self):
        self.__ui.selfIp_lab.setText(get_host_ip())

    def exit_webScanner(self):
        """
        点击退出按钮弹出对话框
        :return:
        """
        msgBox = QMessageBox()
        msgBox.setIcon(QMessageBox.NoIcon)
        msgBox.setWindowTitle("退出程序")
        msgBox.setText("是否退出程序？");
        msgBox.setStandardButtons(QMessageBox.Yes | QMessageBox.No);
        msgBox.setDefaultButton(QMessageBox.No);

        result = msgBox.exec()

        if result == QMessageBox.Yes:
            self.close()

    def arp_scan(self, ip_list):
        """
        对直连设备进行ping扫描可能实用性很差，因为现在设备的个人防火墙默认禁用了ping功能，
        但是对直连设备进行arp扫描是非常实用的，因为每个设备都会对arp请求进行回应
        :param ip_list:
        :return:
        """
        arp_queue = Queue()
        for ip in ip_list:
            self.__ui.statusbar.showMessage("当前任务: 正在探测" + ip)
            scan = threading.Thread(target=arp_request, args=(ip, arp_queue))
            time.sleep(0.1)
            scan.start()
            QtWidgets.QApplication.processEvents()
        self.__ui.statusbar.clearMessage()

        ip_mac_list = []
        while True:
            if arp_queue.empty():
                break;
            else:
                ip, mac = arp_queue.get()
                ip_mac_list.append((ip, mac))
        return ip_mac_list

    def icmp_scan(self, ip_list):
        icmp_queue = Queue()
        for ip in ip_list:
            self.__ui.statusbar.showMessage("当前任务: 正在探测" + ip)
            scan = threading.Thread(target=ping_one, args=(ip, icmp_queue))
            time.sleep(0.1)
            scan.start()
            QtWidgets.QApplication.processEvents()
        self.__ui.statusbar.clearMessage()
        ip_list = []
        while True:
            if icmp_queue.empty():
                break;
            else:
                ip = icmp_queue.get()
                ip_list.append(ip)
        return ip_list

    def syn_443_scan(self, ip_list):
        syn_443_queue = Queue()
        for ip in ip_list:
            self.__ui.statusbar.showMessage("当前任务: 正在探测" + ip)
            scan = threading.Thread(target=syn_443, args=(ip, syn_443_queue))
            time.sleep(0.1)
            scan.start()
            QtWidgets.QApplication.processEvents()
        self.__ui.statusbar.clearMessage()
        ip_list = []
        while True:
            if syn_443_queue.empty():
                break;
            else:
                ip = syn_443_queue.get()
                ip_list.append(ip)
        return ip_list

    def ack_80_scan(self, ip_list):
        ack_80_queue = Queue()
        for ip in ip_list:
            self.__ui.statusbar.showMessage("当前任务: 正在探测" + ip)
            scan = threading.Thread(target=ack_80, args=(ip, ack_80_queue))
            time.sleep(0.1)
            scan.start()
            QtWidgets.QApplication.processEvents()
        self.__ui.statusbar.clearMessage()
        ip_list = []
        while True:
            if ack_80_queue.empty():
                break;
            else:
                ip = ack_80_queue.get()
                ip_list.append(ip)
        return ip_list

    def syn_scan(self, ip, start_port, end_port):
        syn_queue = Queue()
        if start_port == "" and end_port == "":
            port_settings = Settings()
            for port in port_settings.all_port:
                self.__ui.statusbar.showMessage("当前任务: 正在探测" + str(port) + " 端口")
                scan = threading.Thread(target=syn_one, args=(ip, port, syn_queue))
                time.sleep(0.1)
                scan.start()
                QtWidgets.QApplication.processEvents()
            self.__ui.statusbar.clearMessage()
            port_list = []
            while True:
                if syn_queue.empty():
                    break;
                else:
                    port = syn_queue.get()
                    port_list.append(port)
            return port_list

        else:
            for port in range(int(start_port), int(end_port) + 1):
                self.__ui.statusbar.showMessage("当前任务: 正在探测" + str(port) + " 端口")
                scan = threading.Thread(target=syn_one, args=(ip, port, syn_queue))
                time.sleep(0.1)
                scan.start()
                QtWidgets.QApplication.processEvents()
            self.__ui.statusbar.clearMessage()
            port_list = []
            while True:
                if syn_queue.empty():
                    break;
                else:
                    port = syn_queue.get()
                    port_list.append(port)
            return port_list

    def fin_scan(self, ip, start_port, end_port):
        fin_queue = Queue()
        if start_port == "" and end_port == "":
            port_settings = Settings()
            for port in port_settings.all_port:
                # print("正在探测 ", str(port), " 端口")
                self.__ui.statusbar.showMessage("当前任务: 正在探测" + str(port) + " 端口")
                scan = threading.Thread(target=fin_one, args=(ip, port, fin_queue))
                time.sleep(0.1)
                scan.start()
                QtWidgets.QApplication.processEvents()
            self.__ui.statusbar.clearMessage()
            port_list = []
            while True:
                if fin_queue.empty():
                    break;
                else:
                    port = fin_queue.get()
                    port_list.append(port)
            return port_list

        else:
            for port in range(int(start_port), int(end_port) + 1):
                # print("正在探测 ", port, " 端口")
                self.__ui.statusbar.showMessage("当前任务: 正在探测" + str(port) + " 端口")
                scan = threading.Thread(target=fin_one, args=(ip, port, fin_queue))
                time.sleep(0.1)
                scan.start()
                QtWidgets.QApplication.processEvents()
            self.__ui.statusbar.clearMessage()
            port_list = []
            while True:
                if fin_queue.empty():
                    break;
                else:
                    port = fin_queue.get()
                    port_list.append(port)
            return port_list

    def null_scan(self, ip, start_port, end_port):
        null_queue = Queue()
        if start_port == "" and end_port == "":
            port_settings = Settings()
            for port in port_settings.all_port:
                # print("正在探测 ", str(port), " 端口")
                self.__ui.statusbar.showMessage("当前任务: 正在探测" + str(port) + " 端口")
                scan = threading.Thread(target=null_one, args=(ip, port, null_queue))
                time.sleep(0.1)
                scan.start()
                QtWidgets.QApplication.processEvents()
            self.__ui.statusbar.clearMessage()
            port_list = []
            while True:
                if null_queue.empty():
                    break;
                else:
                    port = null_queue.get()
                    port_list.append(port)
            return port_list

        else:
            for port in range(int(start_port), int(end_port) + 1):
                print("正在探测 ", str(port), " 端口")
                self.__ui.statusbar.showMessage("当前任务: 正在探测" + str(port) + " 端口")
                scan = threading.Thread(target=null_one, args=(ip, port, null_queue))
                time.sleep(0.1)
                scan.start()
                QtWidgets.QApplication.processEvents()
            self.__ui.statusbar.clearMessage()
            port_list = []
            while True:
                if null_queue.empty():
                    break;
                else:
                    port = null_queue.get()
                    port_list.append(port)
            return port_list

    def xmas_scan(self, ip, start_port, end_port):
        xmas_queue = Queue()
        if start_port == "" and end_port == "":
            port_settings = Settings()
            for port in port_settings.all_port:
                # print("正在探测 ", str(port), " 端口")
                self.__ui.statusbar.showMessage("当前任务: 正在探测" + str(port) + " 端口")
                scan = threading.Thread(target=xmas_one, args=(ip, port, xmas_queue))
                time.sleep(0.1)
                scan.start()
                QtWidgets.QApplication.processEvents()
            self.__ui.statusbar.clearMessage()
            port_list = []
            while True:
                if xmas_queue.empty():
                    break;
                else:
                    port = xmas_queue.get()
                    port_list.append(port)
            return port_list

        else:
            for port in range(int(start_port), int(end_port) + 1):
                # print("正在探测 ", port, " 端口")
                self.__ui.statusbar.showMessage("当前任务: 正在探测" + str(port) + " 端口")
                scan = threading.Thread(target=xmas_one, args=(ip, port, xmas_queue))
                time.sleep(0.1)
                scan.start()
                QtWidgets.QApplication.processEvents()
            self.__ui.statusbar.clearMessage()
            port_list = []
            while True:
                if xmas_queue.empty():
                    break;
                else:
                    port = xmas_queue.get()
                    port_list.append(port)
            return port_list

    def udp_scan(self, ip, start_port, end_port):
        udp_queue = Queue()
        if start_port == "" and end_port == "":
            port_settings = Settings()
            for port in port_settings.all_port:
                # print("正在探测 ", str(port), " 端口")
                self.__ui.statusbar.showMessage("当前任务: 正在探测" + str(port) + " 端口")
                scan = threading.Thread(target=udp_one, args=(ip, port, udp_queue))
                time.sleep(0.1)
                scan.start()
                QtWidgets.QApplication.processEvents()
            self.__ui.statusbar.clearMessage()
            port_list = []
            while True:
                if udp_queue.empty():
                    break;
                else:
                    port = udp_queue.get()
                    port_list.append(port)
            return port_list

        else:
            for port in range(int(start_port), int(end_port) + 1):
                # print("正在探测 ", port, " 端口")
                self.__ui.statusbar.showMessage("当前任务: 正在探测" + str(port) + " 端口")
                scan = threading.Thread(target=udp_one, args=(ip, port, udp_queue))
                time.sleep(0.1)
                scan.start()
                QtWidgets.QApplication.processEvents()
            self.__ui.statusbar.clearMessage()
            port_list = []
            while True:
                if udp_queue.empty():
                    break;
                else:
                    port = udp_queue.get()
                    port_list.append(port)
            return port_list

    # 主机探测面板
    def clear_hostScan_TestBrowser(self):
        self.__ui.hostScan_textBrowser.clear()

    def enable_startHostScan_btn(self):
        ip_address = self.__ui.hostAdd_lnEd.text()
        check_ip = CheckIpAddress(ip_address)
        self.ip_list = check_ip.check()

        if self.ip_list is not None:
            self.__ui.start_HostScan_btn.setEnabled(True)
            self.__ui.start_HostScan_btn.setText("开始探测")
        else:
            self.__ui.start_HostScan_btn.setEnabled(False)
            self.__ui.start_HostScan_btn.setText("请输入正确格式的主机地址")

    def start_HostScan(self):
        # print("开始扫描")

        comb = self.__ui.hostScan_com.currentText()

        if comb == "arp scan":
            t1 = time.time()
            active_ip_mac = self.arp_scan(self.ip_list)
            self.__ui.hostScan_textBrowser.append("<font color='#ffe7d1'>" + "ARP扫描开始>>>>>" + "</font><br/><br/>")
            if len(active_ip_mac) == 0:
                self.__ui.hostScan_textBrowser.append("<font color='#25ee24'>" + "什么也没探测出来" + "</font><br/>")
            for ip, mac in active_ip_mac:
                # 使用字符编码来替换掉原特殊字符
                self.__ui.hostScan_textBrowser.append(
                    "<font color='#25ee24'>" + "[+] " + ip + " &nbsp;&nbsp;&nbsp;&lt;&lt;&#61;&#61;&#61;&gt;&gt;&nbsp;&nbsp;&nbsp; " + mac + " &nbsp;&nbsp;&nbsp; 在线" + "</font>")
            t2 = time.time()
            run_time = t2 - t1
            self.__ui.hostScan_textBrowser.append("<br/><font color='#ffe7d1'>" + "----------共计用时: " + str(
                round(run_time, 2)) + " s--------------" + "</font><br/><br/>")

        elif comb == "icmp scan":
            t1 = time.time()
            active_ip = self.icmp_scan(self.ip_list)
            self.__ui.hostScan_textBrowser.append("<font color='#ffe7d1'>" + "ICMP扫描开始>>>>>" + "</font><br/><br/>")
            if len(active_ip) == 0:
                self.__ui.hostScan_textBrowser.append("<font color='#25ee24'>" + "什么也没探测出来" + "</font><br/>")
            for ip in active_ip:
                # 使用字符编码来替换掉原特殊字符
                self.__ui.hostScan_textBrowser.append(
                    "<font color='#25ee24'>" + "[+] " + ip + " &nbsp;&nbsp;&nbsp; 在线" + "</font>")
            t2 = time.time()
            run_time = t2 - t1
            self.__ui.hostScan_textBrowser.append("<br/><font color='#ffe7d1'>" + "----------共计用时: " + str(
                round(run_time, 2)) + " s--------------" + "</font><br/><br/>")

        elif comb == "syn_443 scan":
            t1 = time.time()
            active_ip = self.syn_443_scan(self.ip_list)
            self.__ui.hostScan_textBrowser.append("<font color='#ffe7d1'>" + "syn扫描开始>>>>>" + "</font><br/><br/>")
            if len(active_ip) == 0:
                self.__ui.hostScan_textBrowser.append("<font color='#25ee24'>" + "什么也没探测出来" + "</font><br/>")
            for ip in active_ip:
                # 使用字符编码来替换掉原特殊字符
                self.__ui.hostScan_textBrowser.append(
                    "<font color='#25ee24'>" + "[+] " + ip + " &nbsp;&nbsp;&nbsp; 在线" + "</font>")
            t2 = time.time()
            run_time = t2 - t1
            self.__ui.hostScan_textBrowser.append("<br/><font color='#ffe7d1'>" + "----------共计用时: " + str(
                round(run_time, 2)) + " s--------------" + "</font><br/><br/>")

        elif comb == "ack_80 scan":
            t1 = time.time()
            active_ip = self.ack_80_scan(self.ip_list)
            self.__ui.hostScan_textBrowser.append("<font color='#ffe7d1'>" + "ack扫描开始>>>>>" + "</font><br/><br/>")
            if len(active_ip) == 0:
                self.__ui.hostScan_textBrowser.append("<font color='#25ee24'>" + "什么也没探测出来" + "</font><br/>")
            for ip in active_ip:
                # 使用字符编码来替换掉原特殊字符
                self.__ui.hostScan_textBrowser.append(
                    "<font color='#25ee24'>" + "[+] " + ip + " &nbsp;&nbsp;&nbsp; 在线" + "</font>")
            t2 = time.time()
            run_time = t2 - t1
            self.__ui.hostScan_textBrowser.append("<br/><font color='#ffe7d1'>" + "----------共计用时: " + str(
                round(run_time, 2)) + " s--------------" + "</font><br/><br/>")

    # 端口探测面板
    def clear_PortScan_TestBrowser(self):
        self.__ui.PortScan_textBrowser.clear()

    def enable_startPortScan_btn(self):
        ip_address = self.__ui.PortAdd_lnEd.text()
        start_port = self.__ui.PortScan_startPort_lnEd.text()
        end_port = self.__ui.PortScan_endPort_lnEd.text()

        check_ip = CheckIpAddress(ip_address).check_singleIp()
        check_port = CheckPort(start_port, end_port)

        if check_ip is not False and check_port.check() is True:
            self.__ui.start_PortScan_btn.setEnabled(True)
            self.__ui.start_PortScan_btn.setText("开始探测")
        else:
            self.__ui.start_PortScan_btn.setEnabled(False)
            self.__ui.start_PortScan_btn.setText("请输入正确格式的主机地址")

    def start_PortScan(self):
        print("开始扫描")
        ip = self.__ui.PortAdd_lnEd.text()
        start_port = self.__ui.PortScan_startPort_lnEd.text()
        end_port = self.__ui.PortScan_endPort_lnEd.text()

        comb = self.__ui.PortScan_com.currentText()

        if comb == "SYN 扫描":
            print("正在探测", ip, "请稍等~")
            self.__ui.PortScan_textBrowser.append("<font color='#ffe7d1'>" + "syn扫描开始>>>>>" + "</font><br/><br/>")
            t1 = time.time()
            if arp_request(ip) != ip and ping_one(ip) != ip and syn_443(ip) != ip and ack_80(ip) != ip:
                print("什么也没探测出来~")
                self.__ui.PortScan_textBrowser.append("<font color='#25ee24'>" + "什么也没探测出来" + "</font><br/>")
            else:
                port_list = self.syn_scan(ip, start_port, end_port)
                if len(port_list) <= 0:
                    print("什么也没探测出来~")
                    self.__ui.PortScan_textBrowser.append("<font color='#25ee24'>" + "什么也没探测出来" + "</font><br/>")
                else:
                    for port in port_list:
                        print("[+]", ip, ":", port, "端口开放")
                        self.__ui.PortScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] " + str(ip) + "&nbsp;:&nbsp;" + str(
                                port) + "&nbsp;&nbsp;&nbsp;端口开放</font>")
            t2 = time.time()
            run_time = t2 - t1
            print('共计用时: ', round(run_time, 2))
            self.__ui.PortScan_textBrowser.append("<br/><font color='#ffe7d1'>" + "----------共计用时: " + str(
                round(run_time, 2)) + " s--------------" + "</font><br/><br/>")
        elif comb == "FIN 扫描":
            print("正在探测", ip, "请稍等~")
            self.__ui.PortScan_textBrowser.append("<font color='#ffe7d1'>" + "fin扫描开始>>>>>" + "</font><br/><br/>")
            t1 = time.time()
            if ping_one(ip) != ip and ack_80(ip) != ip:
                print("什么也没探测出来~")
                self.__ui.PortScan_textBrowser.append("<font color='#25ee24'>" + "什么也没探测出来" + "</font><br/>")
            else:
                port_list = self.fin_scan(ip, start_port, end_port)
                if len(port_list) <= 0:
                    print("什么也没探测出来~")
                    self.__ui.PortScan_textBrowser.append("<font color='#25ee24'>" + "什么也没探测出来" + "</font><br/>")
                else:
                    for port in port_list:
                        print("[+]", ip, ":", port, "端口开放或无法确定")
                        self.__ui.PortScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] " + str(ip) + "&nbsp;:&nbsp;" + str(
                                port) + "&nbsp;&nbsp;&nbsp;端口开放或无法确定</font>")
            t2 = time.time()
            run_time = t2 - t1
            print('共计用时: ', round(run_time, 2))
            self.__ui.PortScan_textBrowser.append("<br/><font color='#ffe7d1'>" + "----------共计用时: " + str(
                round(run_time, 2)) + " s--------------" + "</font><br/><br/>")
        elif comb == "NULL 扫描":
            print("正在探测", ip, "请稍等~")
            self.__ui.PortScan_textBrowser.append("<font color='#ffe7d1'>" + "null扫描开始>>>>>" + "</font><br/><br/>")
            t1 = time.time()
            if ping_one(ip) != ip and ack_80(ip) != ip:
                print("什么也没探测出来~")
                self.__ui.PortScan_textBrowser.append("<font color='#25ee24'>" + "什么也没探测出来" + "</font><br/>")
            else:
                port_list = self.null_scan(ip, start_port, end_port)
                if len(port_list) <= 0:
                    print("什么也没探测出来~")
                    self.__ui.PortScan_textBrowser.append("<font color='#25ee24'>" + "什么也没探测出来" + "</font><br/>")
                else:
                    for port in port_list:
                        print("[+]", ip, ":", port, "端口开放或无法确定")
                        self.__ui.PortScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] " + str(ip) + "&nbsp;:&nbsp;" + str(
                                port) + "&nbsp;&nbsp;&nbsp;端口开放或无法确定</font>")
            t2 = time.time()
            run_time = t2 - t1
            print('共计用时: ', round(run_time, 2))
            self.__ui.PortScan_textBrowser.append("<br/><font color='#ffe7d1'>" + "----------共计用时: " + str(
                round(run_time, 2)) + " s--------------" + "</font><br/><br/>")
        elif comb == "XMAS 扫描":
            print("正在探测", ip, "请稍等~")
            self.__ui.PortScan_textBrowser.append("<font color='#ffe7d1'>" + "xmas扫描开始>>>>>" + "</font><br/><br/>")
            t1 = time.time()
            if ping_one(ip) != ip and ack_80(ip) != ip:
                print("什么也没探测出来~")
                self.__ui.PortScan_textBrowser.append("<font color='#25ee24'>" + "什么也没探测出来" + "</font><br/>")
            else:
                port_list = self.xmas_scan(ip, start_port, end_port)
                if len(port_list) <= 0:
                    print("什么也没探测出来~")
                    self.__ui.PortScan_textBrowser.append("<font color='#25ee24'>" + "什么也没探测出来" + "</font><br/>")
                else:
                    for port in port_list:
                        print("[+]", ip, ":", port, "端口开放或无法确定")
                        self.__ui.PortScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] " + str(ip) + "&nbsp;:&nbsp;" + str(
                                port) + "&nbsp;&nbsp;&nbsp;端口开放或无法确定</font>")
            t2 = time.time()
            run_time = t2 - t1
            print('共计用时: ', round(run_time, 2))
            self.__ui.PortScan_textBrowser.append("<br/><font color='#ffe7d1'>" + "----------共计用时: " + str(
                round(run_time, 2)) + " s--------------" + "</font><br/><br/>")
        elif comb == "UDP 扫描":
            print("正在探测", ip, "请稍等~")
            self.__ui.PortScan_textBrowser.append("<font color='#ffe7d1'>" + "udp扫描开始>>>>>" + "</font><br/><br/>")
            t1 = time.time()
            if ping_one(ip) != ip and ack_80(ip) != ip:
                print("什么也没探测出来~")
                self.__ui.PortScan_textBrowser.append("<font color='#25ee24'>" + "什么也没探测出来" + "</font><br/>")
            else:
                port_list = self.udp_scan(ip, start_port, end_port)
                if len(port_list) <= 0:
                    print("什么也没探测出来~")
                    self.__ui.PortScan_textBrowser.append("<font color='#25ee24'>" + "什么也没探测出来" + "</font><br/>")
                else:
                    for port in port_list:
                        print("[+]", ip, ":", port, "端口开放或无法确定")
                        self.__ui.PortScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] " + str(ip) + "&nbsp;:&nbsp;" + str(
                                port) + "&nbsp;&nbsp;&nbsp;端口开放或无法确定</font>")
            t2 = time.time()
            run_time = t2 - t1
            print('共计用时: ', round(run_time, 2))
            self.__ui.PortScan_textBrowser.append("<br/><font color='#ffe7d1'>" + "----------共计用时: " + str(
                round(run_time, 2)) + " s--------------" + "</font><br/><br/>")

    # 服务识别面板
    def clear_ServiceScan_TestBrowser(self):
        self.__ui.ServiceScan_textBrowser.clear()

    def enable_startServiceScan_btn(self):
        ip_address = self.__ui.ServiceAdd_lnEd.text()

        check_ip = CheckIpAddress(ip_address).check_singleIp()
        if check_ip is not False:
            self.__ui.start_ServiceScan_btn.setEnabled(True)
            self.__ui.start_ServiceScan_btn.setText("开始探测")
        else:
            self.__ui.start_ServiceScan_btn.setEnabled(False)
            self.__ui.start_ServiceScan_btn.setText("请输入正确格式的主机地址")

    def start_ServiceScan(self):
        print("开始扫描")
        ip = self.__ui.ServiceAdd_lnEd.text()
        self.__ui.statusbar.showMessage("正在扫描 " + ip + " 请稍等~")
        QtWidgets.QApplication.processEvents()
        nm = nmap.PortScanner()
        QtWidgets.QApplication.processEvents()
        self.__ui.statusbar.clearMessage()
        print("正在探测", ip, "请稍等~")
        self.__ui.ServiceScan_textBrowser.append(
            "<font color='#ffe7d1'>" + "正在扫描" + ip + "请稍等>>>>>" + "</font><br/><br/>")
        t1 = time.time()
        # 配置nmap扫描参数
        scan_raw_result = nm.scan(hosts=ip, arguments='-v -n -A')

        for host, result in scan_raw_result["scan"].items():
            if result['status']['state'] == 'up':
                print(ip + " 主机存活~")
                try:
                    self.__ui.ServiceScan_textBrowser.append(
                        "<font color='#25ee24'>" + "======TCP端口========</font>")

                    for port in result['tcp']:
                        self.__ui.ServiceScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] 端口号&nbsp;:&nbsp;" + str(port) + "</font>")
                        print("端口号: ", port)
                        self.__ui.ServiceScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] 名字&nbsp;:&nbsp;" + result['tcp'][port]['name'] + "</font>")
                        print("名字: ", result['tcp'][port]['name'])
                        self.__ui.ServiceScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] 产品&nbsp;:&nbsp;" + result['tcp'][port][
                                'product'] + "</font>")
                        print("产品: ", result['tcp'][port]['product'])
                        self.__ui.ServiceScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] 版本&nbsp;:&nbsp;" + result['tcp'][port][
                                'version'] + "</font>")
                        print("版本: ", result['tcp'][port]['version'])
                except Exception as e:
                    self.__ui.ServiceScan_textBrowser.append(
                        "<font color='#25ee24'>" + "None </font>")
                    pass

                try:
                    self.__ui.ServiceScan_textBrowser.append(
                        "<font color='#25ee24'>" + "======UDP端口========</font>")
                    for port in result['udp']:
                        print('udp 进入~')
                        print("端口号: ", port)
                        self.__ui.ServiceScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] 端口号&nbsp;:&nbsp;" + str(port) + "</font>")
                        print("名字: ", result['udp'][port]['name'])
                        self.__ui.ServiceScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] 名字&nbsp;:&nbsp;" + result['udp'][port]['name'] + "</font>")
                        print("产品: ", result['udp'][port]['product'])
                        self.__ui.ServiceScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] 产品&nbsp;:&nbsp;" + result['udp'][port][
                                'product'] + "</font>")
                        print("版本: ", result['udp'][port]['version'])
                        self.__ui.ServiceScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] 版本&nbsp;:&nbsp;" + result['udp'][port][
                                'version'] + "</font>")
                except Exception as e:
                    self.__ui.ServiceScan_textBrowser.append(
                        "<font color='#25ee24'>" + "None </font>")
                    pass
            else:
                self.__ui.ServiceScan_textBrowser.append("<font color='#25ee24'>" + "什么也没探测出来" + "</font><br/>")

            t2 = time.time()
            run_time = t2 - t1
            print('共计用时: ', round(run_time, 2))
            self.__ui.ServiceScan_textBrowser.append("<br/><font color='#ffe7d1'>" + "----------共计用时: " + str(
                round(run_time, 2)) + " s--------------" + "</font><br/><br/>")

    # 操作系统探测
    def clear_OSscan_TestBrowser(self):
        self.__ui.OSscan_textBrowser.clear()

    def enable_startOSscan_btn(self):
        ip_address = self.__ui.OSAdd_lnEd.text()

        check_ip = CheckIpAddress(ip_address).check_singleIp()
        if check_ip is not False:
            self.__ui.start_OSscan_btn.setEnabled(True)
            self.__ui.start_OSscan_btn.setText("开始探测")
        else:
            self.__ui.start_OSscan_btn.setEnabled(False)
            self.__ui.start_OSscan_btn.setText("请输入正确格式的主机地址")

    def method1_ping(self, host):
        ans, uans = sr(IP(dst=host) / ICMP(), timeout=5, verbose=False)
        if len(ans) == 0:
            print("对方没有相应ICMP包")
            self.__ui.OSscan_textBrowser.append(
                "<font color='#25ee24'>" + "对方没有相应ICMP包 </font>")
        elif int(ans[0][1].fields['ttl']) <= 64:
            print("回送ICMP包TTL值为: " + str(ans[0][1].fields['ttl']))
            self.__ui.OSscan_textBrowser.append(
                "<font color='#25ee24'>" + "回送ICMP包TTL值为: " + str(ans[0][1].fields['ttl']) + "</font>")

            print("回送ICMP包TTL值小于65，操作系统推测结果: Linux系列")
            self.__ui.OSscan_textBrowser.append(
                "<font color='#25ee24'>" + "回送ICMP包TTL值小于65，操作系统推测结果: Linux系列</font>")

            self.os_is_linux.append(1)
        else:
            print("回送ICMP包TTL值为: " + str(ans[0][1].fields['ttl']))
            self.__ui.OSscan_textBrowser.append(
                "<font color='#25ee24'>" + "回送ICMP包TTL值为: " + str(ans[0][1].fields['ttl']) + "</font>")

            print("回送ICMP包TTL值大于64，操作系统推测结果: Windows系列")
            self.__ui.OSscan_textBrowser.append(
                "<font color='#25ee24'>" + "回送ICMP包TTL值小于65，操作系统推测结果: Windows系列</font>")
            self.os_is_linux.append(0)

    def os_syn_one(self, hostname, port, queue=None):
        try:
            syn = sr1(IP(dst=hostname) / TCP(dport=port, flags="S"), timeout=10, verbose=0)
            if syn is not None:
                if syn[1].fields["flags"] == "SA":
                    if queue is not None:
                        # print(port, "开放")
                        queue.put(port)
                    else:
                        print(port, "开放")
        except Exception as e:
            pass

    def os_port_scan(self, ip):
        syn_queue = Queue()
        all_port = Settings().all_port
        for port in all_port:
            self.__ui.statusbar.showMessage("当前任务: 正在探测" + str(port) + " 端口")
            scan = multiprocessing.Process(target=self.os_syn_one, args=(ip, port, syn_queue))
            time.sleep(0.01)
            scan.start()
            QtWidgets.QApplication.processEvents()
        self.__ui.statusbar.clearMessage()
        while True:
            if syn_queue.empty():
                # print("syn_queue啥东西都没有~")
                break
            else:
                port = syn_queue.get()
                # print(port, "----开放")
                self.os_active_port.append(port)

    def method2_fin(self, host, port_list):
        try:
            for port in port_list:
                fin = sr(IP(dst=host) / TCP(dport=port, flags="F"), timeout=10, verbose=0)
                if len(fin[0][TCP]) > 0:
                    if fin[0][0][1][1].fields["flags"] == "RA":
                        print("向开放端口发送FIN包回应RESET包，操作系统推测结果:Windows系列")
                        self.__ui.OSscan_textBrowser.append(
                            "<font color='#25ee24'>" + "向开放端口发送FIN包回应RESET包，操作系统推测结果:Windows系列</font>")
                        self.os_is_linux.append(0)
                        break
                else:
                    print("向开放端口发送FIN包无响应，操作系统推测结果: Linux系列")
                    self.__ui.OSscan_textBrowser.append(
                        "<font color='#25ee24'>" + "向开放端口发送FIN包无响应，操作系统推测结果: Linux系列</font>")
                    self.os_is_linux.append(1)
                    break
        except Exception as e:
            pass

    def method3_syn(self, host, port_list):
        try:
            for port in port_list:
                syn = sr(IP(dst=host) / TCP(dport=port, flags="SE"), timeout=5, verbose=0)
                if len(syn[0][TCP]) > 0:
                    print("回应包TCP标志位为: " + str(syn[0][0][1][1].flags))
                    self.__ui.OSscan_textBrowser.append(
                        "<font color='#25ee24'>" + "回应包TCP标志位为: " + str(syn[0][0][1][1].flags) + "</font>")
                    if syn[0][0][1][1].flags == "SAE":
                        print("标记位探测，在SYN包TCP头中设置未定义的TCP标记SAE，操作系统推测结果:低于2.0.35版本的Linux系列")
                        self.__ui.OSscan_textBrowser.append(
                            "<font color='#25ee24'>" + "标记位探测，在SYN包TCP头中设置未定义的TCP标记SAE，操作系统推测结果:"
                                                       "低于2.0.35版本的Linux系列</font>")
                        self.os_is_linux.append(1)
                        break
                    else:
                        print("标记位探测，在SYN包TCP头中设置未定义的TCP标记SAE，操作系统推测结果:高于2.0.35版本的Linux系列或Windows系列")
                        self.__ui.OSscan_textBrowser.append(
                            "<font color='#25ee24'>" + "标记位探测，在SYN包TCP头中设置未定义的TCP标记SAE，操作系统推测结果:"
                                                       "高于2.0.35版本的Linux系列或Windows系列</font>")
                    break
        except Exception as e:
            pass

    def method4_window(self, host, port_list):
        try:
            for port in port_list:
                syn = sr(IP(dst=host) / TCP(dport=port, flags="S"), timeout=5, verbose=0)
                if len(syn[0][TCP]) > 0:
                    print("返回数据包的窗口大小为: " + str(syn[0][0][1][1].fields["window"]))
                    self.__ui.OSscan_textBrowser.append(
                        "<font color='#25ee24'>" + "返回数据包的窗口大小为: " + str(syn[0][0][1][1].fields["window"]) + "</font>")
                    if syn[0][0][1][1].fields["window"] == 16430:
                        print("操作系统推测结果:Windows系列")
                        self.__ui.OSscan_textBrowser.append(
                            "<font color='#25ee24'>" + "操作系统推测结果:Windows系列</font>")
                        self.os_is_linux.append(0)
                        break
                    else:
                        print("操作系统推测结果:Linux系列或Windows系列")
                        self.__ui.OSscan_textBrowser.append(
                            "<font color='#25ee24'>" + "操作系统推测结果:Linux系列或Windows系列</font>")
                    break
        except Exception as e:
            pass

    def method5_ack(self, host, inactive_port_list):
        try:
            for port in inactive_port_list:
                ack = sr(IP(dst=host) / TCP(dport=port, flags="PFU"), timeout=5, verbose=0)
                if len(ack[0][TCP]) > 0:
                    print("ack: " + str(ack[0][0][1][1].fields["ack"]))
                    self.__ui.OSscan_textBrowser.append(
                        "<font color='#25ee24'>" + "ack: " + str(ack[0][0][1][1].fields["ack"]) + "</font>")
                    print("seq: " + str(ack[0][0][1][1].fields["seq"]))
                    self.__ui.OSscan_textBrowser.append(
                        "<font color='#25ee24'>" + "seq: " + str(ack[0][0][1][1].fields["seq"]) + "</font>")
                    if int(ack[0][0][1][1].fields["seq"]) + 1 == int(ack[0][0][1][1].fields["ack"]):
                        print("向一个关闭的TCP端口发送一个FIN | PSH | URG包，ack值为seq+1，操作系统推测结果:Windows系列")
                        self.__ui.OSscan_textBrowser.append(
                            "<font color='#25ee24'>" + "向一个关闭的TCP端口发送一个FIN | PSH | URG包，ack值为seq+1，"
                                                       "操作系统推测结果:Windows系列</font>")
                        self.os_is_linux.append(0)
                        break
                    else:
                        print("向一个关闭的TCP端口发送一个FIN | PSH | URG包，操作系统推测结果:Linux系列或Windows系列")
                        self.__ui.OSscan_textBrowser.append(
                            "<font color='#25ee24'>" + "向一个关闭的TCP端口发送一个FIN | PSH | URG包，"
                                                       "操作系统推测结果:Linux系列或Windows系列</font>")
                    break
        except Exception as e:
            pass

    def start_OSscan(self):

        host = self.__ui.OSAdd_lnEd.text()
        print("正在探测: " + str(host))
        self.__ui.OSscan_textBrowser.append(
            "<font color='#ffe7d1'>" + "正在探测" + host + "请稍等>>>>>" + "</font><br/><br/>")
        t1 = time.time()

        self.method1_ping(host)
        self.os_port_scan(host)

        for i in range(1, 11):
            if i not in self.os_active_port:
                self.os_inactive_port.append(i)

        print("开放端口: " + str(self.os_active_port))
        self.__ui.OSscan_textBrowser.append(
            "<font color='#25ee24'>" + "开放端口: " + str(self.os_active_port) + "</font>")

        print("不开放端口: " + str(self.os_inactive_port), "...")
        self.__ui.OSscan_textBrowser.append(
            "<font color='#25ee24'>" + "不开放端口: " + str(self.os_inactive_port) + "..." + "</font>")

        self.method2_fin(host, self.os_active_port)
        self.method3_syn(host, self.os_active_port)
        self.method4_window(host, self.os_active_port)
        self.method5_ack(host, self.os_inactive_port)

        num = len(self.os_is_linux)
        for os in self.os_is_linux:
            if os == 0:
                self.os_windows_rate += 1
            elif os == 1:
                self.os_linux_rate += 1
        windows_rate = round((self.os_windows_rate / num) * 100, 3)
        linux_rate = round((self.os_linux_rate / num) * 100, 3)

        print("最终结果：")
        self.__ui.OSscan_textBrowser.append(
            "<font color='#25ee24'>" + "最终结果: </font>")

        print("Linux系列概率: " + str(linux_rate))
        self.__ui.OSscan_textBrowser.append(
            "<font color='#25ee24'>" + "Linux系列概率: " + str(linux_rate) + "</font>")

        print("Windows系列概率: ", str(windows_rate))
        self.__ui.OSscan_textBrowser.append(
            "<font color='#25ee24'>" + "Windows系列概率: " + str(windows_rate) + "</font>")

        self.os_active_port = []
        self.os_inactive_port = []
        self.os_windows_rate = 0
        self.os_linux_rate = 0
        self.os_is_linux = []

        t2 = time.time()
        run_time = t2 - t1
        print('共计用时: ', round(run_time, 2))
        self.__ui.OSscan_textBrowser.append("<br/><font color='#ffe7d1'>" + "----------共计用时: " + str(
            round(run_time, 2)) + " s--------------" + "</font><br/><br/>")

    # FTP弱口令检测
    def get_ftpIp(self):
        SHODAN_API_KEY = "JBk8vtewlHrlSumHI28PfcSWVTCyJYPl"
        api = shodan.Shodan(SHODAN_API_KEY)
        try:
            # 搜索 Shodan
            results = api.search('ftp')
            QtWidgets.QApplication.processEvents()
            self.__ui.statusbar.clearMessage()
            for result in results['matches']:
                # print(result['ip_str'])
                self.__ui.statusbar.showMessage("请稍等~")
                flag = self.__FlagEditable
                aItem = QListWidgetItem()
                str_ip = str(result['ip_str'])
                aItem.setText(str_ip)
                aItem.setCheckState(Qt.Unchecked)
                aItem.setFlags(flag)
                self.__ui.ftp_ip_list.addItem(aItem)
                self.ftp_ip_list.append(str_ip)
                QtWidgets.QApplication.processEvents()
            self.__ui.statusbar.clearMessage()
        except Exception as e:
            print(e)
            pass

    def add_ftpIp(self):
        flag = self.__FlagEditable
        aItem = QListWidgetItem()
        str_ip = "192.168.43.1"
        aItem.setText(str_ip)
        aItem.setCheckState(Qt.Unchecked)
        aItem.setFlags(flag)
        self.__ui.ftp_ip_list.addItem(aItem)
        self.ftp_ip_list.append(str_ip)

    def del_ftpIp(self):
        i = 0
        while True:
            try:
                aItem = self.__ui.ftp_ip_list.item(i)
                if str(aItem.checkState()) == str(Qt.Checked):
                    self.__ui.ftp_ip_list.takeItem(i)
                    i = 0
                else:
                    i += 1
            except Exception as e:
                print(str(e))
                break

    def add_ftpUserName(self):
        flag = self.__FlagEditable
        aItem = QListWidgetItem()
        str_username = "username"
        aItem.setText(str_username)
        aItem.setCheckState(Qt.Unchecked)
        aItem.setFlags(flag)
        self.__ui.ftp_userName_list.addItem(aItem)
        self.ftp_username_list.append(str_username)

    def del_ftpUserName(self):
        i = 0
        while True:
            try:
                aItem = self.__ui.ftp_userName_list.item(i)
                if str(aItem.checkState()) == str(Qt.Checked):
                    self.__ui.ftp_userName_list.takeItem(i)
                    i = 0
                else:
                    i += 1
            except Exception as e:
                print(str(e))
                break

    def add_ftpPassword(self):
        flag = self.__FlagEditable
        aItem = QListWidgetItem()
        str_password = "password"
        aItem.setText(str_password)
        aItem.setCheckState(Qt.Unchecked)
        aItem.setFlags(flag)
        self.__ui.ftp_password_list.addItem((aItem))
        self.ftp_password_list.append(str_password)

    def del_ftpPassword(self):
        i = 0
        while True:
            try:
                aItem = self.__ui.ftp_password_list.item(i)
                if str(aItem.checkState()) == str(Qt.Checked):
                    self.__ui.ftp_password_list.takeItem(i)
                    i = 0
                else:
                    i += 1
            except Exception as e:
                print(str(e))
                break

    def ftp_ip_list_drop_release(self, event):
        self.__ui.ftp_ip_list.clear()
        filename = event.mimeData().urls()[0].path()  # 完整文件名
        with open(filename, 'r') as f:
            for line in f:
                ip = line.replace("\n", '')
                flag = self.__FlagEditable
                aItem = QListWidgetItem()
                aItem.setText(ip)
                aItem.setCheckState(Qt.Unchecked)
                aItem.setFlags(flag)
                self.__ui.ftp_ip_list.addItem(aItem)
                self.ftp_ip_list.append(ip)
        event.accept()

    def ftp_username_list_drop_release(self, event):
        self.__ui.ftp_userName_list.clear()
        filename = event.mimeData().urls()[0].path()  # 完整文件名
        with open(filename, 'r') as f:
            for line in f:
                username = line.replace("\n", '')
                flag = self.__FlagEditable
                aItem = QListWidgetItem()
                aItem.setText(username)
                aItem.setCheckState(Qt.Unchecked)
                aItem.setFlags(flag)
                self.__ui.ftp_userName_list.addItem(aItem)
                self.ftp_username_list.append(username)
        event.accept()

    def ftp_password_list_drop_release(self, event):
        self.__ui.ftp_password_list.clear()
        filename = event.mimeData().urls()[0].path()  # 完整文件名
        with open(filename, 'r') as f:
            for line in f:
                password = line.replace("\n", '')
                flag = self.__FlagEditable
                aItem = QListWidgetItem()
                aItem.setText(password)
                aItem.setCheckState(Qt.Unchecked)
                aItem.setFlags(flag)
                self.__ui.ftp_password_list.addItem(aItem)
                self.ftp_password_list.append(password)
        event.accept()

    def selAll_ip(self, checked):
        if checked == 0:
            for i in range(self.__ui.ftp_ip_list.count()):
                aItem = self.__ui.ftp_ip_list.item(i)
                aItem.setCheckState(Qt.Unchecked)
        else:
            for i in range(self.__ui.ftp_ip_list.count()):
                aItem = self.__ui.ftp_ip_list.item(i)
                aItem.setCheckState(Qt.Checked)

    def invs_ip(self):
        for i in range(self.__ui.ftp_ip_list.count()):
            aItem = self.__ui.ftp_ip_list.item(i)
            if aItem.checkState() != Qt.Checked:
                aItem.setCheckState(Qt.Checked)
            else:
                aItem.setCheckState(Qt.Unchecked)

    def selAll_username(self, checked):
        if checked == 0:
            for i in range(self.__ui.ftp_userName_list.count()):
                aItem = self.__ui.ftp_userName_list.item(i)
                aItem.setCheckState(Qt.Unchecked)
        else:
            for i in range(self.__ui.ftp_userName_list.count()):
                aItem = self.__ui.ftp_userName_list.item(i)
                aItem.setCheckState(Qt.Checked)

    def invs_username(self):
        for i in range(self.__ui.ftp_userName_list.count()):
            aItem = self.__ui.ftp_userName_list.item(i)
            if aItem.checkState() != Qt.Checked:
                aItem.setCheckState(Qt.Checked)
            else:
                aItem.setCheckState(Qt.Unchecked)

    def selAll_password(self, checked):
        if checked == 0:
            for i in range(self.__ui.ftp_password_list.count()):
                aItem = self.__ui.ftp_password_list.item(i)
                aItem.setCheckState(Qt.Unchecked)
        else:
            for i in range(self.__ui.ftp_password_list.count()):
                aItem = self.__ui.ftp_password_list.item(i)
                aItem.setCheckState(Qt.Checked)

    def invs_password(self):
        for i in range(self.__ui.ftp_password_list.count()):
            aItem = self.__ui.ftp_password_list.item(i)
            if aItem.checkState() != Qt.Checked:
                aItem.setCheckState(Qt.Checked)
            else:
                aItem.setCheckState(Qt.Unchecked)

    def anon_Login(self, host):
        ftp = FTP()
        try:
            self.__ui.statusbar.showMessage("当前任务: 正在尝试匿名登录 " + host)
            self.__ui.ftp_curr_Ip_lab.setText(host)
            ftp.connect(host=host, timeout=20)
            ftp.login()
            ftp.quit()
            print('匿名登录成功,' + ' IP:' + host)
            anon_str = '匿名登录成功,' + ' IP:' + host
            self.__ui.ftp_textBrowser.append(anon_str)
            self.ftp_ip_list.remove(host)
            self.__ui.statusbar.clearMessage()

            return True
        except Exception as e:
            pass

    def login(self, host, username, password):
        ftp = FTP()
        try:
            self.__ui.statusbar.showMessage("匿名登录失败，当前任务: 正在尝试登录: " + host + " 用户名: "
                                            + username + " 密码: " + password)
            self.__ui.ftp_curr_Ip_lab.setText(host)
            ftp.connect(host=host, timeout=20)
            ftp.login(username, password)
            ftp.quit()
            login_str = '破解成功,用户名：' + username + '，密码：' + password + ',IP:' + host
            self.__ui.ftp_textBrowser.append(login_str)
            print('破解成功,用户名：' + username + '，密码：' + password + ',IP:' + host)
            self.__ui.statusbar.clearMessage()
            return True
        except Exception as e:
            pass

    def start_FtpScan(self):
        try:
            print("start_ftpScan")
            print("ip地址列表")
            print(self.ftp_ip_list)
            print("用户名列表")
            print(self.ftp_username_list)
            print("密码列表")
            print(self.ftp_password_list)
            for ip in self.ftp_ip_list:
                try:
                    scan = threading.Thread(target=self.anon_Login, args=(ip,))
                    scan.start()
                except Exception as e:
                    pass
                QtWidgets.QApplication.processEvents()
            for ip in self.ftp_ip_list:
                for username in self.ftp_username_list:
                    for password in self.ftp_password_list:
                        try:
                            scan = threading.Thread(target=self.login, args=(ip, username, password))
                            scan.start()
                        except Exception as e:
                            pass
                        QtWidgets.QApplication.processEvents()
            self.__ui.ftp_curr_Ip_lab.setText("None")
            self.__ui.statusbar.clearMessage()
            self.ftp_ip_list.clear()
            self.ftp_username_list.clear()
            self.ftp_password_list.clear()
        except Exception as e:
            print(e)
            pass


if __name__ == '__main__':
    app = QApplication(sys.argv)
    # qApp.processEvents(QEventLoop.ExcludeUserInputEvents)
    mainWindow = WelcomePane()
    mainWindow.setWindowTitle("网络扫描器")
    mainWindow.show()
    sys.exit(app.exec_())
