import threading
import time
from queue import Queue

import nmap
import shodan
from PyQt5 import QtCore
from PyQt5.QtCore import pyqtSignal
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp, sr

from scan.settings import Settings


class ArpScanThread(QtCore.QThread):

    start_scan_signal = pyqtSignal(str)
    end_scan_signal = pyqtSignal(float)

    statusbar_show_ip_signal = pyqtSignal(str)
    statusbar_clear_ip_signal = pyqtSignal()

    nothing_scaned_signal = pyqtSignal()
    success_scaned_signal = pyqtSignal(str, str)

    def __init__(self, ip_list, parent=None):
        super(ArpScanThread, self).__init__(parent)
        self.ip_list = ip_list

    def arp_request(self, ip, queue=None):
        try:
            ans, uans = srp(Ether(dst="FF:FF:FF:fF:fF:FF") / ARP(pdst=ip), timeout=10, verbose=False)
            if len(ans) > 0:
                ip = ans[0][1][1].fields['psrc']
                MAC = ans[0][1][1].fields['hwsrc']
                print(ip, ' <<===>> ', MAC, ' is up')
                self.success_scaned_signal.emit(ip, MAC)
                queue.put((ip, MAC))
        except Exception as e:
            pass

    def run(self):
        t1 = time.time()
        arp_queue = Queue()

        self.start_scan_signal.emit("ARP")
        for ip in self.ip_list:
            self.statusbar_show_ip_signal.emit(ip)
            scan = threading.Thread(target=self.arp_request, args=(ip, arp_queue))
            time.sleep(0.1)
            scan.start()

        time.sleep(1)
        ip_list = []
        while True:
            if arp_queue.empty():
                break
            else:
                ip, mac = arp_queue.get()
                ip_list.append((ip, mac))

        count = len(ip_list)
        if count == 0:
            print("什么也没有探测到")
            self.nothing_scaned_signal.emit()

        self.statusbar_clear_ip_signal.emit()
        t2 = time.time()
        run_time = t2 - t1
        self.end_scan_signal.emit(run_time)


class IcmpScanThread(QtCore.QThread):

    start_scan_signal = pyqtSignal(str)
    end_scan_signal = pyqtSignal(float)

    statusbar_show_ip_signal = pyqtSignal(str)
    statusbar_clear_ip_signal = pyqtSignal()

    nothing_scaned_signal = pyqtSignal()
    success_scaned_signal = pyqtSignal(str)

    def __init__(self, ip_list, parent=None):
        super(IcmpScanThread, self).__init__(parent)
        self.ip_list = ip_list

    def ping_one(self, ip, queue=None):
        try:
            ans, uans = sr(IP(dst=ip) / ICMP(), timeout=5, verbose=False)
            if len(ans) > 0:
                ip = ans[0][1].fields['src']
                print(ip, ' is up')
                self.success_scaned_signal.emit(ip)
                queue.put(ip)
        except Exception as e:
            pass

    def run(self):
        t1 = time.time()
        icmp_queue = Queue()

        self.start_scan_signal.emit("ICMP")
        for ip in self.ip_list:
            self.statusbar_show_ip_signal.emit(ip)
            scan = threading.Thread(target=self.ping_one, args=(ip, icmp_queue))
            time.sleep(0.1)
            scan.start()

        time.sleep(1)
        ip_list = []
        while True:
            if icmp_queue.empty():
                break
            else:
                ip = icmp_queue.get()
                ip_list.append(ip)

        count = len(ip_list)
        if count == 0:
            print("什么也没有探测到")
            self.nothing_scaned_signal.emit()

        self.statusbar_clear_ip_signal.emit()
        t2 = time.time()
        run_time = t2 - t1
        self.end_scan_signal.emit(run_time)


class SYN443ScanThread(QtCore.QThread):

    start_scan_signal = pyqtSignal(str)
    end_scan_signal = pyqtSignal(float)

    statusbar_show_ip_signal = pyqtSignal(str)
    statusbar_clear_ip_signal = pyqtSignal()

    nothing_scaned_signal = pyqtSignal()
    success_scaned_signal = pyqtSignal(str)

    def __init__(self, ip_list, parent=None):
        super(SYN443ScanThread, self).__init__(parent)
        self.ip_list = ip_list

    def syn_443(self, ip, queue=None):
        try:
            ans, uans = sr(IP(dst=ip) / TCP(dport=443, flags="S"), timeout=5, verbose=False)
            if len(ans) > 0:
                ip = ans[0][1].fields['src']
                print(ip, ' is up')
                self.success_scaned_signal.emit(ip)
                queue.put(ip)
        except Exception as e:
            pass

    def run(self):
        t1 = time.time()
        syn443_queue = Queue()

        self.start_scan_signal.emit("SYN_443")
        for ip in self.ip_list:
            self.statusbar_show_ip_signal.emit(ip)
            scan = threading.Thread(target=self.syn_443, args=(ip, syn443_queue))
            time.sleep(0.1)
            scan.start()

        time.sleep(1)
        ip_list = []
        while True:
            if syn443_queue.empty():
                break
            else:
                ip = syn443_queue.get()
                ip_list.append(ip)

        count = len(ip_list)
        if count == 0:
            print("什么也没有探测到")
            self.nothing_scaned_signal.emit()

        self.statusbar_clear_ip_signal.emit()
        t2 = time.time()
        run_time = t2 - t1
        self.end_scan_signal.emit(run_time)


class ACK80ScanThread(QtCore.QThread):

    start_scan_signal = pyqtSignal(str)
    end_scan_signal = pyqtSignal(float)

    statusbar_show_ip_signal = pyqtSignal(str)
    statusbar_clear_ip_signal = pyqtSignal()

    nothing_scaned_signal = pyqtSignal()
    success_scaned_signal = pyqtSignal(str)

    def __init__(self, ip_list, parent=None):
        super(ACK80ScanThread, self).__init__(parent)
        self.ip_list = ip_list

    def ack_80(self, ip, queue=None):
        try:
            ans, uans = sr(IP(dst=ip) / TCP(dport=80, flags="A"), timeout=5, verbose=False)
            if len(ans) > 0:
                ip = ans[0][1].fields['src']
                print(ip, ' is up')
                self.success_scaned_signal.emit(ip)
                queue.put(ip)
        except Exception as e:
            pass

    def run(self):
        t1 = time.time()
        ack80_queue = Queue()

        self.start_scan_signal.emit("ACK_80")
        for ip in self.ip_list:
            self.statusbar_show_ip_signal.emit(ip)
            scan = threading.Thread(target=self.ack_80, args=(ip, ack80_queue))
            time.sleep(0.1)
            scan.start()

        time.sleep(1)
        ip_list = []
        while True:
            if ack80_queue.empty():
                break
            else:
                ip = ack80_queue.get()
                ip_list.append(ip)

        count = len(ip_list)
        if count == 0:
            print("什么也没有探测到")
            self.nothing_scaned_signal.emit()

        self.statusbar_clear_ip_signal.emit()
        t2 = time.time()
        run_time = t2 - t1
        self.end_scan_signal.emit(run_time)


class IsHostAlive(QtCore.QThread):

    start_scan_signal = pyqtSignal(str)
    end_scan_signal = pyqtSignal(float)

    statusbar_show_signal = pyqtSignal()
    statusbar_clear_signal = pyqtSignal()

    host_is_done_signal = pyqtSignal()
    start_port_scan_signal = pyqtSignal(str, str, str)

    def __init__(self, ip, start_port, end_port, method, parent=None):
        super(IsHostAlive, self).__init__(parent)
        self.ip = ip
        self.start_port = start_port
        self.end_port = end_port
        self.method = method

    def arp_request(self, ip_address):
        try:
            ans, uans = srp(Ether(dst="FF:FF:FF:fF:fF:FF") / ARP(pdst=ip_address), timeout=10, verbose=False)
            if len(ans) > 0:
                ip = ans[0][1][1].fields['psrc']
                MAC = ans[0][1][1].fields['hwsrc']
                print(ip, ' <<===>> ', MAC, ' is up')
                return ip
        except Exception as e:
            pass

    def ping_one(self, host):
        try:
            ans, uans = sr(IP(dst=host) / ICMP(), timeout=5, verbose=False)
            if len(ans) > 0:
                ip = ans[0][1].fields['src']
                print(ip, ' is up')
                return ip
        except Exception as e:
            pass

    def syn_443(self, host):
        try:
            ans, uans = sr(IP(dst=host) / TCP(dport=443, flags="S"), timeout=5, verbose=False)
            if len(ans) > 0:
                ip = ans[0][1].fields['src']
                print(ip, ' is up')
                return ip
        except Exception as e:
            pass

    def ack_80(self, host):
        """
        如果一个主机存在的话，向它发送一个flags为ACK包的话，无论端口是否关闭都会有返回一个flags为RST包，
        如果是主机不存在的话就会一个数据包都不会返回
        :param host:
        :param queue:
        :return:
        """
        try:
            ans, uans = sr(IP(dst=host) / TCP(dport=80, flags="A"), timeout=5, verbose=False)
            if len(ans) > 0:
                ip = ans[0][1].fields['src']
                print(ip, ' is up')
                return ip
        except Exception as e:
            pass

    def run(self):
        t1 = time.time()
        self.start_scan_signal.emit(self.method)
        self.statusbar_show_signal.emit()
        if self.arp_request(self.ip) != self.ip and self.syn_443(self.ip) != self.ip:
            self.host_is_done_signal.emit()
            self.statusbar_clear_signal.emit()
            t2 = time.time()
            run_time = t2 - t1
            self.end_scan_signal.emit(run_time)
        else:
            self.statusbar_clear_signal.emit()
            self.start_port_scan_signal.emit(self.ip, self.start_port, self.end_port)


class SYNScanThread(QtCore.QThread):

    statusbar_show_port_signal = pyqtSignal(int)
    statusbar_clear_port_signal = pyqtSignal()

    nothing_scaned_signal = pyqtSignal()
    success_scaned_signal = pyqtSignal(str, int)

    end_scan_signal = pyqtSignal(float)

    def __init__(self, ip, start_port, end_port, parent=None):
        super(SYNScanThread, self).__init__(parent)
        self.ip = ip
        self.start_port = start_port
        self.end_port = end_port

    def syn_one(self, ip, port, queue=None):
        try:
            ans, uans = sr(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=1, verbose=False)
            if len(ans) > 0:
                if ans[0][1][1].fields['flags'] == 'SA':
                    print("[+] %s %d \033[92m Open \033[0m" % (ip, port))
                    self.success_scaned_signal.emit(ip, port)
                    queue.put(port)
        except Exception as e:
            pass

    def run(self):
        t1 = time.time()
        syn_queue = Queue()
        port_list = []
        if self.start_port == "" and self.end_port == "":
            port_settings = Settings()
            for port in port_settings.all_port:
                self.statusbar_show_port_signal.emit(port)
                scan = threading.Thread(target=self.syn_one, args=(self.ip, port, syn_queue))
                time.sleep(0.1)
                scan.start()
            self.statusbar_clear_port_signal.emit()
            while True:
                if syn_queue.empty():
                    break
                else:
                    port = syn_queue.get()
                    port_list.append(port)

        else:
            for port in range(int(self.start_port), int(self.end_port) + 1):
                self.statusbar_show_port_signal.emit(port)
                scan = threading.Thread(target=self.syn_one, args=(self.ip, port, syn_queue))
                time.sleep(0.1)
                scan.start()
            self.statusbar_clear_port_signal.emit()
            while True:
                if syn_queue.empty():
                    break
                else:
                    port = syn_queue.get()
                    port_list.append(port)

        count = len(port_list)
        if count == 0:
            print("什么也没有探测到")
            self.nothing_scaned_signal.emit()
        t2 = time.time()
        run_time = t2 - t1
        self.end_scan_signal.emit(run_time)


class FINScanThread(QtCore.QThread):

    statusbar_show_port_signal = pyqtSignal(int)
    statusbar_clear_port_signal = pyqtSignal()

    nothing_scaned_signal = pyqtSignal()
    success_scaned_signal = pyqtSignal(str, int)

    end_scan_signal = pyqtSignal(float)

    def __init__(self, ip, start_port, end_port, parent=None):
        super(FINScanThread, self).__init__(parent)
        self.ip = ip
        self.start_port = start_port
        self.end_port = end_port

    def fin_one(self, ip, port, queue=None):
        try:
            ans, uans = sr(IP(dst=ip) / TCP(dport=port, flags="F"), timeout=1, verbose=False)
            if len(ans) == 0:
                print("[+] %s  %d \033[91m Open | filtered\033[0m" % (ip, port))
                self.success_scaned_signal.emit(ip, port)
                queue.put(port)
        except Exception as e:
            pass

    def run(self):
        t1 = time.time()
        syn_queue = Queue()
        port_list = []
        if self.start_port == "" and self.end_port == "":
            port_settings = Settings()
            for port in port_settings.all_port:
                self.statusbar_show_port_signal.emit(port)
                scan = threading.Thread(target=self.fin_one, args=(self.ip, port, syn_queue))
                time.sleep(0.1)
                scan.start()
            self.statusbar_clear_port_signal.emit()
            while True:
                if syn_queue.empty():
                    break
                else:
                    port = syn_queue.get()
                    port_list.append(port)

        else:
            for port in range(int(self.start_port), int(self.end_port) + 1):
                self.statusbar_show_port_signal.emit(port)
                scan = threading.Thread(target=self.fin_one, args=(self.ip, port, syn_queue))
                time.sleep(0.1)
                scan.start()
            self.statusbar_clear_port_signal.emit()
            while True:
                if syn_queue.empty():
                    break
                else:
                    port = syn_queue.get()
                    port_list.append(port)

        count = len(port_list)
        if count == 0:
            print("什么也没有探测到")
            self.nothing_scaned_signal.emit()
        t2 = time.time()
        run_time = t2 - t1
        self.end_scan_signal.emit(run_time)


class NULLScanThread(QtCore.QThread):
    statusbar_show_port_signal = pyqtSignal(int)
    statusbar_clear_port_signal = pyqtSignal()

    nothing_scaned_signal = pyqtSignal()
    success_scaned_signal = pyqtSignal(str, int)

    end_scan_signal = pyqtSignal(float)

    def __init__(self, ip, start_port, end_port, parent=None):
        super(NULLScanThread, self).__init__(parent)
        self.ip = ip
        self.start_port = start_port
        self.end_port = end_port

    def null_one(self, ip, port, queue=None):
        try:
            ans, uans = sr(IP(dst=ip) / TCP(dport=port, flags=""), timeout=1, verbose=False)
            if len(ans) == 0:
                print("[+] %s  %d \033[91m Open | filtered\033[0m" % (ip, port))
                self.success_scaned_signal.emit(ip, port)
                queue.put(port)
        except Exception as e:
            pass

    def run(self):
        t1 = time.time()
        syn_queue = Queue()
        port_list = []
        if self.start_port == "" and self.end_port == "":
            port_settings = Settings()
            for port in port_settings.all_port:
                self.statusbar_show_port_signal.emit(port)
                scan = threading.Thread(target=self.null_one, args=(self.ip, port, syn_queue))
                time.sleep(0.1)
                scan.start()
            self.statusbar_clear_port_signal.emit()
            while True:
                if syn_queue.empty():
                    break
                else:
                    port = syn_queue.get()
                    port_list.append(port)

        else:
            for port in range(int(self.start_port), int(self.end_port) + 1):
                self.statusbar_show_port_signal.emit(port)
                scan = threading.Thread(target=self.null_one, args=(self.ip, port, syn_queue))
                time.sleep(0.1)
                scan.start()
            self.statusbar_clear_port_signal.emit()
            while True:
                if syn_queue.empty():
                    break
                else:
                    port = syn_queue.get()
                    port_list.append(port)

        count = len(port_list)
        if count == 0:
            print("什么也没有探测到")
            self.nothing_scaned_signal.emit()
        t2 = time.time()
        run_time = t2 - t1
        self.end_scan_signal.emit(run_time)


class XMASScanThread(QtCore.QThread):

    statusbar_show_port_signal = pyqtSignal(int)
    statusbar_clear_port_signal = pyqtSignal()

    nothing_scaned_signal = pyqtSignal()
    success_scaned_signal = pyqtSignal(str, int)

    end_scan_signal = pyqtSignal(float)

    def __init__(self, ip, start_port, end_port, parent=None):
        super(XMASScanThread, self).__init__(parent)
        self.ip = ip
        self.start_port = start_port
        self.end_port = end_port

    def xmas_one(self, ip, port, queue=None):
        try:
            ans, uans = sr(IP(dst=ip) / TCP(dport=port, flags="PFU"), timeout=1, verbose=False)
            if len(ans) == 0:
                print("[+] %s  %d \033[91m Open | filtered\033[0m" % (ip, port))
                self.success_scaned_signal.emit(ip, port)
                queue.put(port)
        except Exception as e:
            pass

    def run(self):
        t1 = time.time()
        syn_queue = Queue()
        port_list = []
        if self.start_port == "" and self.end_port == "":
            port_settings = Settings()
            for port in port_settings.all_port:
                self.statusbar_show_port_signal.emit(port)
                scan = threading.Thread(target=self.xmas_one, args=(self.ip, port, syn_queue))
                time.sleep(0.1)
                scan.start()
            self.statusbar_clear_port_signal.emit()
            while True:
                if syn_queue.empty():
                    break
                else:
                    port = syn_queue.get()
                    port_list.append(port)

        else:
            for port in range(int(self.start_port), int(self.end_port) + 1):
                self.statusbar_show_port_signal.emit(port)
                scan = threading.Thread(target=self.xmas_one, args=(self.ip, port, syn_queue))
                time.sleep(0.1)
                scan.start()
            self.statusbar_clear_port_signal.emit()
            while True:
                if syn_queue.empty():
                    break
                else:
                    port = syn_queue.get()
                    port_list.append(port)

        count = len(port_list)
        if count == 0:
            print("什么也没有探测到")
            self.nothing_scaned_signal.emit()
        t2 = time.time()
        run_time = t2 - t1
        self.end_scan_signal.emit(run_time)


class UDPScanThread(QtCore.QThread):

    statusbar_show_port_signal = pyqtSignal(int)
    statusbar_clear_port_signal = pyqtSignal()

    nothing_scaned_signal = pyqtSignal()
    success_scaned_signal = pyqtSignal(str, int)

    end_scan_signal = pyqtSignal(float)

    def __init__(self, ip, start_port, end_port, parent=None):
        super(UDPScanThread, self).__init__(parent)
        self.ip = ip
        self.start_port = start_port
        self.end_port = end_port

    def udp_one(self, ip, port, queue=None):
        try:
            ans, uans = sr(IP(dst=ip) / UDP(dport=port), timeout=0.08, verbose=False)
            if len(ans) == 0:
                print("[+] %s  %d \033[91m Open | filtered\033[0m" % (ip, port))
                self.success_scaned_signal.emit(ip, port)
                queue.put(port)
        except Exception as e:
            pass

    def run(self):
        t1 = time.time()
        syn_queue = Queue()
        port_list = []
        if self.start_port == "" and self.end_port == "":
            port_settings = Settings()
            for port in port_settings.all_port:
                self.statusbar_show_port_signal.emit(port)
                scan = threading.Thread(target=self.udp_one, args=(self.ip, port, syn_queue))
                time.sleep(0.1)
                scan.start()
            self.statusbar_clear_port_signal.emit()
            while True:
                if syn_queue.empty():
                    break
                else:
                    port = syn_queue.get()
                    port_list.append(port)

        else:
            for port in range(int(self.start_port), int(self.end_port) + 1):
                self.statusbar_show_port_signal.emit(port)
                scan = threading.Thread(target=self.udp_one, args=(self.ip, port, syn_queue))
                time.sleep(0.1)
                scan.start()
            self.statusbar_clear_port_signal.emit()
            while True:
                if syn_queue.empty():
                    break
                else:
                    port = syn_queue.get()
                    port_list.append(port)

        count = len(port_list)
        if count == 0:
            print("什么也没有探测到")
            self.nothing_scaned_signal.emit()
        t2 = time.time()
        run_time = t2 - t1
        self.end_scan_signal.emit(run_time)


class ServiceScanThread(QtCore.QThread):

    start_scan_signal = pyqtSignal(str)
    end_scan_signal = pyqtSignal(float, dict)

    def __init__(self, ip,  parent=None):
        super(ServiceScanThread, self).__init__(parent)
        self.ip = ip

    def run(self):
        self.start_scan_signal.emit(self.ip)
        t1 = time.time()
        nm = nmap.PortScanner()
        # 配置nmap扫描参数
        scan_raw_result = nm.scan(hosts=self.ip, arguments='-v -n -A')
        t2 = time.time()
        run_time = t2 - t1
        self.end_scan_signal.emit(run_time, scan_raw_result)


class GetFTPHost(QtCore.QThread):

    ftp_wait_signal = pyqtSignal()
    ftp_end_signal = pyqtSignal(dict)

    def __init__(self, parent=None):
        super(GetFTPHost, self).__init__(parent)

    def run(self):
        """在这里输入你自己的shodan的key，没有需要自己在网站注册"""
        SHODAN_API_KEY = ""
        api = shodan.Shodan(SHODAN_API_KEY)
        try:
            # 搜索 Shodan
            self.ftp_wait_signal.emit()
            results = api.search('ftp')
            self.ftp_end_signal.emit(results)

        except Exception as e:
            print(e)
            pass
