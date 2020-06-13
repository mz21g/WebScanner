import multiprocessing
import random
import sys
import threading
import time
from ftplib import FTP
from multiprocessing import Queue
import requests
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMainWindow, QApplication, QPushButton, QMessageBox, QListWidgetItem, QDialog
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.sendrecv import sr1, sr

from resources.UI.welcome_ui import Ui_MainWindow
from scan.settings import Settings
from scan.threads import ArpScanThread, IcmpScanThread, SYN443ScanThread, ACK80ScanThread, SYNScanThread, IsHostAlive, \
    FINScanThread, NULLScanThread, XMASScanThread, UDPScanThread, GetFTPHost
from utensil.tools import CheckIpAddress, get_host_ip, CheckPort, CheckUrl


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
        self.__ui.SqlInjuAdd_lnEd.setAttribute(QtCore.Qt.WA_MacShowFocusRect, 0)
        self.__ui.SqlInjuUserAgent_lnEd.setAttribute(QtCore.Qt.WA_MacShowFocusRect, 0)
        self.__ui.SqlInjuCookie_lnEd.setAttribute(QtCore.Qt.WA_MacShowFocusRect, 0)

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

        self.check_url = {}

        self.MYSQL_ERROR = "You have an error in your SQL syntax;"

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

# -----------------------UI界面槽函数-------------------------------

    def init_host_scan(self, method):
        self.__ui.hostScan_textBrowser.append("<font color='#ffe7d1'>" + method + "扫描开始>>>>>" + "</font><br/><br/>")

    def init_port_scan(self, method):
        self.__ui.PortScan_textBrowser.append("<font color='#ffe7d1'>" + method + "扫描开始>>>>>" + "</font><br/><br/>")

    def last_host_scan(self, run_time):
        self.__ui.hostScan_textBrowser.append("<br/><font color='#ffe7d1'>" + "----------共计用时: " + str(
            round(run_time, 2)) + " s--------------" + "</font><br/><br/>")

    def last_port_scan(self, run_time):
        self.__ui.PortScan_textBrowser.append("<br/><font color='#ffe7d1'>" + "----------共计用时: " + str(
            round(run_time, 2)) + " s--------------" + "</font><br/><br/>")

    def host_scan_nothing_scaned(self):
        self.__ui.hostScan_textBrowser.append("<font color='#25ee24'>" + "什么也没探测出来" + "</font><br/>")

    def port_scan_nothing_scaned(self):
        self.__ui.PortScan_textBrowser.append("<font color='#25ee24'>" + "什么也没探测出来" + "</font><br/>")

    def show_host_scan_status(self, ip):
        self.__ui.statusbar.showMessage("当前任务: 正在探测" + str(ip))

    def show_port_scan_status(self, port):
        self.__ui.statusbar.showMessage("当前任务: 正在探测" + str(port) + " 端口")

    def clear_status(self):
        self.__ui.statusbar.clearMessage()

    def success_ip_mac_scaned(self, ip, mac):
        self.__ui.hostScan_textBrowser.append(
            "<font color='#25ee24'>" + "[+] " + ip + " &nbsp;&nbsp;&nbsp;&lt;&lt;&#61;&#61;&#61;&gt;&gt;&nbsp;&nbsp;&nbsp; " + mac + " &nbsp;&nbsp;&nbsp; 在线" + "</font>")

    def success_ip_scaned(self, ip):
        self.__ui.hostScan_textBrowser.append(
            "<font color='#25ee24'>" + "[+] " + ip + " &nbsp;&nbsp;&nbsp; 在线" + "</font>")

    def success_port_scaned(self, ip, port):
        self.__ui.PortScan_textBrowser.append(
            "<font color='#25ee24'>" + "[+] " + str(ip) + "&nbsp;:&nbsp;" + str(
                port) + "&nbsp;&nbsp;&nbsp;端口开放</font>")

    def success_or_not_port_scaned(self, ip, port):
        self.__ui.PortScan_textBrowser.append(
            "<font color='#25ee24'>" + "[+] " + str(ip) + "&nbsp;:&nbsp;" + str(
                port) + "&nbsp;&nbsp;&nbsp;端口开放或无法确定</font>")

    def host_alive_status(self):
        self.__ui.statusbar.showMessage("马上开始探测，请稍等~")

    def ftp_wait_status(self):
        self.__ui.statusbar.showMessage("请稍等~")

# -----------------------------------------------------------------

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

        comb = self.__ui.hostScan_com.currentText()

        if comb == "arp scan":

            self.arpScan_thread = ArpScanThread(self.ip_list)

            self.arpScan_thread.start_scan_signal.connect(self.init_host_scan)
            self.arpScan_thread.end_scan_signal.connect(self.last_host_scan)
            self.arpScan_thread.statusbar_show_ip_signal.connect(self.show_host_scan_status)
            self.arpScan_thread.statusbar_clear_ip_signal.connect(self.clear_status)
            self.arpScan_thread.nothing_scaned_signal.connect(self.host_scan_nothing_scaned)
            self.arpScan_thread.success_scaned_signal.connect(self.success_ip_mac_scaned)

            self.arpScan_thread.start()

        elif comb == "icmp scan":

            self.icmpScan_thread = IcmpScanThread(self.ip_list)

            self.icmpScan_thread.start_scan_signal.connect(self.init_host_scan)
            self.icmpScan_thread.end_scan_signal.connect(self.last_host_scan)
            self.icmpScan_thread.statusbar_show_ip_signal.connect(self.show_host_scan_status)
            self.icmpScan_thread.statusbar_clear_ip_signal.connect(self.clear_status)
            self.icmpScan_thread.nothing_scaned_signal.connect(self.host_scan_nothing_scaned)
            self.icmpScan_thread.success_scaned_signal.connect(self.success_ip_scaned)

            self.icmpScan_thread.start()

        elif comb == "syn_443 scan":

            self.syn443Scan_thread = SYN443ScanThread(self.ip_list)

            self.syn443Scan_thread.start_scan_signal.connect(self.init_host_scan)
            self.syn443Scan_thread.end_scan_signal.connect(self.last_host_scan)
            self.syn443Scan_thread.statusbar_show_ip_signal.connect(self.show_host_scan_status)
            self.syn443Scan_thread.statusbar_clear_ip_signal.connect(self.clear_status)
            self.syn443Scan_thread.nothing_scaned_signal.connect(self.host_scan_nothing_scaned)
            self.syn443Scan_thread.success_scaned_signal.connect(self.success_ip_scaned)

            self.syn443Scan_thread.start()

        elif comb == "ack_80 scan":

            self.ack80Scan_thread = ACK80ScanThread(self.ip_list)

            self.ack80Scan_thread.start_scan_signal.connect(self.init_host_scan)
            self.ack80Scan_thread.end_scan_signal.connect(self.last_host_scan)
            self.ack80Scan_thread.statusbar_show_ip_signal.connect(self.show_host_scan_status)
            self.ack80Scan_thread.statusbar_clear_ip_signal.connect(self.clear_status)
            self.ack80Scan_thread.nothing_scaned_signal.connect(self.host_scan_nothing_scaned)
            self.ack80Scan_thread.success_scaned_signal.connect(self.success_ip_scaned)

            self.ack80Scan_thread.start()

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

    def host_done(self):
        print("目标主机为离线状态~")
        self.__ui.PortScan_textBrowser.append("<font color='#25ee24'>" + "目标主机为离线状态" + "</font><br/>")

    def host_alive_syn(self, ip, start_port, end_port):
        self.synScan_thread = SYNScanThread(ip, start_port, end_port)
        self.synScan_thread.statusbar_show_port_signal.connect(self.show_port_scan_status)
        self.synScan_thread.statusbar_clear_port_signal.connect(self.clear_status)
        self.synScan_thread.nothing_scaned_signal.connect(self.host_scan_nothing_scaned)
        self.synScan_thread.success_scaned_signal.connect(self.success_port_scaned)
        self.synScan_thread.end_scan_signal.connect(self.last_port_scan)
        self.synScan_thread.start()

    def host_alive_fin(self, ip, start_port, end_port):
        self.finScan_thread = FINScanThread(ip, start_port, end_port)
        self.finScan_thread.statusbar_show_port_signal.connect(self.show_port_scan_status)
        self.finScan_thread.statusbar_clear_port_signal.connect(self.clear_status)
        self.finScan_thread.nothing_scaned_signal.connect(self.host_scan_nothing_scaned)
        self.finScan_thread.success_scaned_signal.connect(self.success_or_not_port_scaned)
        self.finScan_thread.end_scan_signal.connect(self.last_port_scan)
        self.finScan_thread.start()

    def host_alive_null(self, ip, start_port, end_port):
        self.nullScan_thread = NULLScanThread(ip, start_port, end_port)
        self.nullScan_thread.statusbar_show_port_signal.connect(self.show_port_scan_status)
        self.nullScan_thread.statusbar_clear_port_signal.connect(self.clear_status)
        self.nullScan_thread.nothing_scaned_signal.connect(self.host_scan_nothing_scaned)
        self.nullScan_thread.success_scaned_signal.connect(self.success_or_not_port_scaned)
        self.nullScan_thread.end_scan_signal.connect(self.last_port_scan)
        self.nullScan_thread.start()

    def host_alive_xmas(self, ip, start_port, end_port):
        self.xmasScan_thread = XMASScanThread(ip, start_port, end_port)
        self.xmasScan_thread.statusbar_show_port_signal.connect(self.show_port_scan_status)
        self.xmasScan_thread.statusbar_clear_port_signal.connect(self.clear_status)
        self.xmasScan_thread.nothing_scaned_signal.connect(self.host_scan_nothing_scaned)
        self.xmasScan_thread.success_scaned_signal.connect(self.success_or_not_port_scaned)
        self.xmasScan_thread.end_scan_signal.connect(self.last_port_scan)
        self.xmasScan_thread.start()

    def host_alive_udp(self, ip, start_port, end_port):
        self.udpScan_thread = UDPScanThread(ip, start_port, end_port)
        self.udpScan_thread.statusbar_show_port_signal.connect(self.show_port_scan_status)
        self.udpScan_thread.statusbar_clear_port_signal.connect(self.clear_status)
        self.udpScan_thread.nothing_scaned_signal.connect(self.host_scan_nothing_scaned)
        self.udpScan_thread.success_scaned_signal.connect(self.success_or_not_port_scaned)
        self.udpScan_thread.end_scan_signal.connect(self.last_port_scan)
        self.udpScan_thread.start()

    def start_PortScan(self):
        print("开始扫描")
        ip = self.__ui.PortAdd_lnEd.text()
        start_port = self.__ui.PortScan_startPort_lnEd.text()
        end_port = self.__ui.PortScan_endPort_lnEd.text()

        comb = self.__ui.PortScan_com.currentText()

        if comb == "SYN 扫描":
            self.isHost_alive = IsHostAlive(ip, start_port, end_port, "SYN")
            self.isHost_alive.start_scan_signal.connect(self.init_port_scan)
            self.isHost_alive.end_scan_signal.connect(self.last_port_scan)
            self.isHost_alive.host_is_done_signal.connect(self.host_done)
            self.isHost_alive.start_port_scan_signal.connect(self.host_alive_syn)
            self.isHost_alive.statusbar_show_signal.connect(self.host_alive_status)
            self.isHost_alive.statusbar_clear_signal.connect(self.clear_status)
            self.isHost_alive.start()

        elif comb == "FIN 扫描":
            self.isHost_alive = IsHostAlive(ip, start_port, end_port, "FIN")
            self.isHost_alive.start_scan_signal.connect(self.init_port_scan)
            self.isHost_alive.end_scan_signal.connect(self.last_port_scan)
            self.isHost_alive.host_is_done_signal.connect(self.host_done)
            self.isHost_alive.start_port_scan_signal.connect(self.host_alive_fin)
            self.isHost_alive.statusbar_show_signal.connect(self.host_alive_status)
            self.isHost_alive.statusbar_clear_signal.connect(self.clear_status)
            self.isHost_alive.start()

        elif comb == "NULL 扫描":
            self.isHost_alive = IsHostAlive(ip, start_port, end_port, "NULL")
            self.isHost_alive.start_scan_signal.connect(self.init_port_scan)
            self.isHost_alive.end_scan_signal.connect(self.last_port_scan)
            self.isHost_alive.host_is_done_signal.connect(self.host_done)
            self.isHost_alive.start_port_scan_signal.connect(self.host_alive_null)
            self.isHost_alive.statusbar_show_signal.connect(self.host_alive_status)
            self.isHost_alive.statusbar_clear_signal.connect(self.clear_status)
            self.isHost_alive.start()

        elif comb == "XMAS 扫描":
            self.isHost_alive = IsHostAlive(ip, start_port, end_port, "XMAS")
            self.isHost_alive.start_scan_signal.connect(self.init_port_scan)
            self.isHost_alive.end_scan_signal.connect(self.last_port_scan)
            self.isHost_alive.host_is_done_signal.connect(self.host_done)
            self.isHost_alive.start_port_scan_signal.connect(self.host_alive_xmas)
            self.isHost_alive.statusbar_show_signal.connect(self.host_alive_status)
            self.isHost_alive.statusbar_clear_signal.connect(self.clear_status)
            self.isHost_alive.start()

        elif comb == "UDP 扫描":
            self.isHost_alive = IsHostAlive(ip, start_port, end_port, "UDP")
            self.isHost_alive.start_scan_signal.connect(self.init_port_scan)
            self.isHost_alive.end_scan_signal.connect(self.last_port_scan)
            self.isHost_alive.host_is_done_signal.connect(self.host_done)
            self.isHost_alive.start_port_scan_signal.connect(self.host_alive_udp)
            self.isHost_alive.statusbar_show_signal.connect(self.host_alive_status)
            self.isHost_alive.statusbar_clear_signal.connect(self.clear_status)
            self.isHost_alive.start()

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

    def init_service(self, ip):
        self.__ui.statusbar.showMessage("正在扫描 " + ip + " 请稍等~")
        self.__ui.ServiceScan_textBrowser.append(
            "<font color='#ffe7d1'>" + "正在扫描" + ip + "请稍等>>>>>" + "</font><br/><br/>")

    def last_service(self, run_time, scan_raw_result):
        for host, result in scan_raw_result["scan"].items():
            if result['status']['state'] == 'up':
                try:
                    self.__ui.ServiceScan_textBrowser.append(
                        "<font color='#25ee24'>" + "======TCP端口========</font>")

                    for port in result['tcp']:
                        self.__ui.ServiceScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] 端口号&nbsp;:&nbsp;" + str(port) + "</font>")
                        self.__ui.ServiceScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] 名字&nbsp;:&nbsp;" + result['tcp'][port]['name'] + "</font>")
                        self.__ui.ServiceScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] 产品&nbsp;:&nbsp;" + result['tcp'][port][
                                'product'] + "</font>")
                        self.__ui.ServiceScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] 版本&nbsp;:&nbsp;" + result['tcp'][port][
                                'version'] + "</font>")
                except Exception as e:
                    self.__ui.ServiceScan_textBrowser.append(
                        "<font color='#25ee24'>" + "None </font>")
                    pass

                try:
                    self.__ui.ServiceScan_textBrowser.append(
                        "<font color='#25ee24'>" + "======UDP端口========</font>")
                    for port in result['udp']:
                        self.__ui.ServiceScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] 端口号&nbsp;:&nbsp;" + str(port) + "</font>")
                        self.__ui.ServiceScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] 名字&nbsp;:&nbsp;" + result['udp'][port]['name'] + "</font>")
                        self.__ui.ServiceScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] 产品&nbsp;:&nbsp;" + result['udp'][port][
                                'product'] + "</font>")
                        self.__ui.ServiceScan_textBrowser.append(
                            "<font color='#25ee24'>" + "[+] 版本&nbsp;:&nbsp;" + result['udp'][port][
                                'version'] + "</font>")
                except Exception as e:
                    self.__ui.ServiceScan_textBrowser.append(
                        "<font color='#25ee24'>" + "None </font>")
                    pass
            else:
                self.__ui.ServiceScan_textBrowser.append("<font color='#25ee24'>" + "什么也没探测出来" + "</font><br/>")

            self.__ui.ServiceScan_textBrowser.append("<br/><font color='#ffe7d1'>" + "----------共计用时: " + str(
                round(run_time, 2)) + " s--------------" + "</font><br/><br/>")
            self.__ui.statusbar.clearMessage()

    def start_ServiceScan(self):
        from scan.threads import ServiceScanThread
        # 新建对象
        ip = self.__ui.ServiceAdd_lnEd.text()
        self.ServiceScan_thread = ServiceScanThread(ip)

        self.ServiceScan_thread.start_scan_signal.connect(self.init_service)
        self.ServiceScan_thread.end_scan_signal.connect(self.last_service)

        # 开始执行run()函数里的内容
        self.ServiceScan_thread.start()

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
            print("对方没有响应ICMP包")
            self.__ui.OSscan_textBrowser.append(
                "<font color='#25ee24'>" + "对方没有响应ICMP包 </font>")
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

    def method6_tos(self, host, inactive_port_list):
        try:
            for port in inactive_port_list:
                ans, uans = sr(IP(dst=host) / UDP(dport=port), timeout=0.08, verbose=False)
                if len(ans) > 0:
                    tos_val = ans[0][1].fields['tos']
                    print("tos: " + hex(tos_val))
                    self.__ui.OSscan_textBrowser.append(
                        "<font color='#25ee24'>" + "tos: " + hex(tos_val) + "</font>")
                    if int(tos_val) == 0xC0:
                        print("对于ICMP的“端口不可达”信息，经过对返回包的TOS值的检查，tos值为0xC0，操作系统推测结果:Linux系列")
                        self.__ui.OSscan_textBrowser.append(
                            "<font color='#25ee24'>" + "对于ICMP的“端口不可达”信息，经过对返回包的TOS值的检查"
                                                       "，tos值为0xC0，操作系统推测结果:Linux系列</font>")
                        self.os_is_linux.append(1)
                        break
                    elif int(tos_val) == 0:
                        print("对于ICMP的“端口不可达”信息，经过对返回包的TOS值的检查，tos值为0，操作系统推测结果:Windows系列")
                        self.__ui.OSscan_textBrowser.append(
                            "<font color='#25ee24'>" + "对于ICMP的“端口不可达”信息，经过对返回包的TOS值的检查"
                                                       "，tos值为0，操作系统推测结果:Windows系列</font>")
                        self.os_is_linux.append(0)
                    break
        except Exception as e:
            pass

    def start_OSscan(self):
        try:
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
            self.method6_tos(host, self.os_inactive_port)

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
        except Exception as e:
            pass

    # FTP弱口令检测
    def ftp_end(self, results):
        for result in results['matches']:
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

    def get_ftpIp(self):

        self.get_host = GetFTPHost()

        self.get_host.ftp_wait_signal.connect(self.ftp_wait_status)
        self.get_host.ftp_end_signal.connect(self.ftp_end)

        self.get_host.start()

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

    # sql注入漏洞检测
    def clear_SqlInjuScan_TestBrowser(self):
        self.__ui.SqlInjuScan_textBrowser.clear()

    def enable_SqlInjuScan_btn(self):
        url = self.__ui.SqlInjuAdd_lnEd.text()
        self.check_url = CheckUrl(url).check_url()

        if self.check_url is not False:
            self.__ui.start_SqlInjuScan_btn.setEnabled(True)
            self.__ui.start_SqlInjuScan_btn.setText("开始检测")
        else:
            self.__ui.start_SqlInjuScan_btn.setEnabled(False)
            self.__ui.start_SqlInjuScan_btn.setText("请输入正确格式的url地址")

    def start_SqlInjuScan(self):
        try:
            user_agent = self.__ui.SqlInjuUserAgent_lnEd.text()
            cookie = self.__ui.SqlInjuCookie_lnEd.text()
            if user_agent is not None:
                if cookie is not None:
                    headers = {'User-Agent': user_agent, 'Cookie': cookie}

            parse_url = self.check_url['url']
            remain = self.check_url['remain']

            id_val = random.randint(1, 100)

            payload_1 = {"%27": "'"}
            payload_2 = {"+and+1%3D1": "and 1=1"}
            payload_3 = {"+and+1%3D2": "and 1=2"}
            payload_4 = {"%27+and+%271%27%3D%271": "' and '1'='1"}
            payload_5 = {"%27+and+%271%27%3D%272": "' and '1'='2"}

            payload_dict = {**payload_1, **payload_2, **payload_3, **payload_4, **payload_5}

            for payload in payload_dict:

                url = parse_url + str(id_val) + payload + remain
                orig_url = self.__ui.SqlInjuAdd_lnEd.text()
                self.__ui.statusbar.showMessage("正在检测 " + orig_url + " 请稍等~")
                self.__ui.statusbar.clearMessage()
                print("正在探测", orig_url, "请稍等~")
                self.__ui.SqlInjuScan_textBrowser.append(
                    "<font color='#ffe7d1'>" + "正在扫描请稍等>>>>>" + "</font><br/><br/>")
                t1 = time.time()

                if headers is not None:
                    r = requests.get(url, headers=headers, timeout=10)
                else:
                    r = requests.get(url, timeout=10)

                origin_html = r.text

                if r.status_code != 200:
                    print("该网页无法正常访问")
                    self.__ui.SqlInjuScan_textBrowser.append("<font color='#25ee24'>" + "该网页无法正常访问" + "</font><br/>")
                else:
                    if self.MYSQL_ERROR not in origin_html:
                        print("什么也没检测出来")
                        self.__ui.SqlInjuScan_textBrowser.append("<font color='#25ee24'>" + "什么也没检测出来" + "</font><br/>")
                        break
                    else:
                        print("检测到sql注入漏洞")
                        self.__ui.SqlInjuScan_textBrowser.append("<font color='#25ee24'>" + "检测到sql注入漏洞" + "</font><br/>")
                        print("原因:")
                        self.__ui.SqlInjuScan_textBrowser.append("<font color='#25ee24'>" + "原因:" + "</font><br/>")
                        print("注入===>> ", payload_dict[payload], " <<===时页面出错，产生You have an error in your SQL syntax语句")
                        self.__ui.SqlInjuScan_textBrowser.append("<font color='#25ee24'>" + "注入( " +
                                                                 str(payload_dict[payload]) +
                                                                 ")时页面出错，产生You have an error in your SQL syntax语句"
                                                                 " </font><br/>")
                        break

            t2 = time.time()
            run_time = t2 - t1
            print('共计用时: ', round(run_time, 2))
            self.__ui.SqlInjuScan_textBrowser.append("<br/><font color='#ffe7d1'>" + "----------共计用时: " + str(
                round(run_time, 2)) + " s--------------" + "</font><br/><br/>")
        except Exception as e:
            print(e)
            self.__ui.SqlInjuScan_textBrowser.append("<font color='#25ee24'>" + str(e) + "</font><br/>")
            t2 = time.time()
            run_time = t2 - t1
            print('共计用时: ', round(run_time, 2))
            self.__ui.SqlInjuScan_textBrowser.append("<br/><font color='#ffe7d1'>" + "----------共计用时: " + str(
                round(run_time, 2)) + " s--------------" + "</font><br/><br/>")
            pass

if __name__ == '__main__':
    app = QApplication(sys.argv)
    mainWindow = WelcomePane()
    mainWindow.setWindowTitle("网络扫描器")
    mainWindow.show()
    sys.exit(app.exec_())

