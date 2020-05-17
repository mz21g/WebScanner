# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'welcome_ui.ui'
#
# Created by: PyQt5 UI code generator 5.14.1
#
# WARNING! All changes made in this file will be lost!


from PyQt5 import QtCore, QtGui, QtWidgets

from utensil.ftp_list import QFtp_list


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(830, 600)
        MainWindow.setMinimumSize(QtCore.QSize(830, 600))
        MainWindow.setMaximumSize(QtCore.QSize(830, 643))
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setMinimumSize(QtCore.QSize(830, 600))
        self.centralwidget.setMaximumSize(QtCore.QSize(830, 600))
        self.centralwidget.setObjectName("centralwidget")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(0, 10, 830, 575))
        self.tabWidget.setMinimumSize(QtCore.QSize(830, 575))
        self.tabWidget.setMaximumSize(QtCore.QSize(830, 570))
        self.tabWidget.setStyleSheet("QTabWidget::pane\n"
                                     "{\n"
                                     "    font: 18pt \"Trebuchet MS\";\n"
                                     "    border-top: 1px solid white;\n"
                                     "    background-color: rgb(23, 23, 23);\n"
                                     "}\n"
                                     "QTabWidget::tab-bar\n"
                                     "{\n"
                                     "    subcontrol-position:center;\n"
                                     "    background-color: rgb(23, 23, 23);\n"
                                     "}\n"
                                     " \n"
                                     "QTabBar::tab\n"
                                     " \n"
                                     "{\n"
                                     "min-width:75px;\n"
                                     "min-height:35px;\n"
                                     "background-color: rgb(23, 23, 23);\n"
                                     "}\n"
                                     " \n"
                                     "QTabBar::tab:selected\n"
                                     " \n"
                                     "{\n"
                                     "color: rgb(255, 121, 0);\n"
                                     "background:transparent;\n"
                                     "    background-color: rgb(53, 54, 54);\n"
                                     "}\n"
                                     " \n"
                                     "QTabBar::tab:!selected\n"
                                     "{\n"
                                     "color: white;\n"
                                     "}\n"
                                     "\n"
                                     "QTabBar::tab:hover\n"
                                     "{\n"
                                     "color: rgb(255, 121, 0);\n"
                                     "}\n"
                                     "")
        self.tabWidget.setUsesScrollButtons(False)
        self.tabWidget.setDocumentMode(True)
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setStyleSheet("QWidget#tab{\n"
                               "    border-image: url(:/background/images/background/webscan.jpg);\n"
                               "}")
        self.tab.setObjectName("tab")
        self.label = QtWidgets.QLabel(self.tab)
        self.label.setGeometry(QtCore.QRect(230, 60, 351, 51))
        self.label.setStyleSheet("color: rgb(255, 255, 255);\n"
                                 "font: 48pt \"Helvetica Neue\";")
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.tab)
        self.label_2.setGeometry(QtCore.QRect(300, 180, 261, 31))
        self.label_2.setStyleSheet("color: rgb(255, 255, 255);\n"
                                   "font: 24pt \".AppleSystemUIFont\";")
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.tab)
        self.label_3.setGeometry(QtCore.QRect(300, 230, 261, 31))
        self.label_3.setStyleSheet("color: rgb(255, 255, 255);\n"
                                   "font: 24pt \".AppleSystemUIFont\";")
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(self.tab)
        self.label_4.setGeometry(QtCore.QRect(300, 280, 161, 31))
        self.label_4.setStyleSheet("color: rgb(255, 255, 255);\n"
                                   "font: 24pt \".AppleSystemUIFont\";")
        self.label_4.setObjectName("label_4")
        self.label_5 = QtWidgets.QLabel(self.tab)
        self.label_5.setGeometry(QtCore.QRect(300, 320, 201, 31))
        self.label_5.setStyleSheet("color: rgb(255, 255, 255);\n"
                                   "font: 24pt \".AppleSystemUIFont\";")
        self.label_5.setObjectName("label_5")
        self.label_6 = QtWidgets.QLabel(self.tab)
        self.label_6.setGeometry(QtCore.QRect(300, 370, 191, 31))
        self.label_6.setStyleSheet("color: rgb(255, 255, 255);\n"
                                   "font: 24pt \".AppleSystemUIFont\";")
        self.label_6.setObjectName("label_6")
        self.label_7 = QtWidgets.QLabel(self.tab)
        self.label_7.setGeometry(QtCore.QRect(210, 450, 421, 61))
        self.label_7.setStyleSheet("color: rgb(255, 255, 255);\n"
                                   "font: 24pt \".AppleSystemUIFont\";")
        self.label_7.setObjectName("label_7")
        self.selfIp_lab = QtWidgets.QLabel(self.tab)
        self.selfIp_lab.setGeometry(QtCore.QRect(660, 10, 171, 21))
        self.selfIp_lab.setStyleSheet("QLabel{\n"
                                      "    color: rgba(255, 255, 255,0.4);\n"
                                      "    font: 24pt \".AppleSystemUIFont\";\n"
                                      "}\n"
                                      "QLabel:hover{\n"
                                      "    color: rgba(255, 255, 255,0.6);\n"
                                      "}")
        self.selfIp_lab.setText("")
        self.selfIp_lab.setObjectName("selfIp_lab")
        self.pushButton = QtWidgets.QPushButton(self.tab)
        self.pushButton.setGeometry(QtCore.QRect(572, 10, 71, 21))
        self.pushButton.setStyleSheet("QPushButton{\n"
                                      "    color: rgba(255, 255, 255,0.4);\n"
                                      "    font: 15pt \".AppleSystemUIFont\";\n"
                                      "    background-color: rgba(255, 255, 255, 0);\n"
                                      "}\n"
                                      "QPushButton:hover{\n"
                                      "    color: rgba(255, 255, 255,0.6);\n"
                                      "}")
        self.pushButton.setObjectName("pushButton")
        self.tabWidget.addTab(self.tab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setStyleSheet("QWidget#tab_2{\n"
                                 "border-image: url(:/background/images/background/webscan.jpg);\n"
                                 "}")
        self.tab_2.setObjectName("tab_2")
        self.hostAdd_lnEd = QtWidgets.QLineEdit(self.tab_2)
        self.hostAdd_lnEd.setGeometry(QtCore.QRect(130, 20, 411, 21))
        self.hostAdd_lnEd.setStyleSheet("background-color: rgba(255,255,255,0.2);\n"
                                        "color: rgb(255, 255, 255);\n"
                                        "border: 1px solid white;\n"
                                        "border-radius: 10px;")
        self.hostAdd_lnEd.setObjectName("hostAdd_lnEd")
        self.label_8 = QtWidgets.QLabel(self.tab_2)
        self.label_8.setGeometry(QtCore.QRect(30, 20, 81, 21))
        self.label_8.setStyleSheet("color: rgb(255, 255, 255);\n"
                                   "font: 18pt \"Al Bayan\";")
        self.label_8.setObjectName("label_8")
        self.start_HostScan_btn = QtWidgets.QPushButton(self.tab_2)
        self.start_HostScan_btn.setEnabled(False)
        self.start_HostScan_btn.setGeometry(QtCore.QRect(30, 60, 591, 31))
        self.start_HostScan_btn.setStyleSheet("QPushButton{\n"
                                              "    background-color: rgba(254, 162, 28, 0.6);\n"
                                              "    color: rgb(238, 243, 243);\n"
                                              "    font: 18pt \"Al Bayan\";\n"
                                              "}\n"
                                              "QPushButton:hover{\n"
                                              "    background-color: rgba(254, 162, 28, 0.7);\n"
                                              "}\n"
                                              "QPushButton:pressed{\n"
                                              "    background-color: rgba(254, 162, 28, 0.8);\n"
                                              "}\n"
                                              "QPushButton:disabled{\n"
                                              "    background-color: rgb(159, 159, 159);\n"
                                              "}")
        self.start_HostScan_btn.setObjectName("start_HostScan_btn")
        self.clear_HostScan_btn = QtWidgets.QPushButton(self.tab_2)
        self.clear_HostScan_btn.setGeometry(QtCore.QRect(680, 60, 121, 31))
        self.clear_HostScan_btn.setStyleSheet("QPushButton{\n"
                                              "    color: rgb(238, 243, 243);\n"
                                              "    font: 18pt \"Al Bayan\";\n"
                                              "    border: 1px solid white;\n"
                                              "    border-radius: 10px;\n"
                                              "}\n"
                                              "QPushButton:hover{\n"
                                              "    background-color: rgba(254, 162, 28, 0.7);\n"
                                              "}\n"
                                              "QPushButton:pressed{\n"
                                              "    background-color: rgba(254, 162, 28, 0.8);\n"
                                              "}")
        self.clear_HostScan_btn.setObjectName("clear_HostScan_btn")
        self.label_9 = QtWidgets.QLabel(self.tab_2)
        self.label_9.setGeometry(QtCore.QRect(570, 20, 81, 21))
        self.label_9.setStyleSheet("color: rgb(255, 255, 255);\n"
                                   "font: 18pt \"Al Bayan\";")
        self.label_9.setObjectName("label_9")
        self.hostScan_com = QtWidgets.QComboBox(self.tab_2)
        self.hostScan_com.setGeometry(QtCore.QRect(670, 20, 131, 21))
        self.hostScan_com.setObjectName("hostScan_com")
        self.hostScan_com.addItem("")
        self.hostScan_com.addItem("")
        self.hostScan_com.addItem("")
        self.hostScan_com.addItem("")
        self.hostScan_textBrowser = QtWidgets.QTextBrowser(self.tab_2)
        self.hostScan_textBrowser.setGeometry(QtCore.QRect(20, 110, 791, 411))
        self.hostScan_textBrowser.setStyleSheet("QTextBrowser{\n"
                                                "    color: rgb(37, 238, 36);\n"
                                                "    font: 18pt \"Trebuchet MS\";\n"
                                                "    background-color: rgba(166, 161, 142, 0.6);\n"
                                                "}")
        self.hostScan_textBrowser.setObjectName("hostScan_textBrowser")
        self.tabWidget.addTab(self.tab_2, "")
        self.tab_3 = QtWidgets.QWidget()
        self.tab_3.setStyleSheet("QWidget#tab_3{\n"
                                 "border-image: url(:/background/images/background/webscan.jpg);\n"
                                 "}")
        self.tab_3.setObjectName("tab_3")
        self.label_10 = QtWidgets.QLabel(self.tab_3)
        self.label_10.setGeometry(QtCore.QRect(30, 20, 81, 21))
        self.label_10.setStyleSheet("color: rgb(255, 255, 255);\n"
                                    "font: 18pt \"Al Bayan\";")
        self.label_10.setObjectName("label_10")
        self.PortAdd_lnEd = QtWidgets.QLineEdit(self.tab_3)
        self.PortAdd_lnEd.setGeometry(QtCore.QRect(130, 20, 411, 21))
        self.PortAdd_lnEd.setStyleSheet("background-color: rgba(255,255,255,0.2);\n"
                                        "color: rgb(255, 255, 255);\n"
                                        "border: 1px solid white;\n"
                                        "border-radius: 10px;")
        self.PortAdd_lnEd.setObjectName("PortAdd_lnEd")
        self.start_PortScan_btn = QtWidgets.QPushButton(self.tab_3)
        self.start_PortScan_btn.setEnabled(False)
        self.start_PortScan_btn.setGeometry(QtCore.QRect(30, 110, 771, 31))
        self.start_PortScan_btn.setStyleSheet("QPushButton{\n"
                                              "    background-color: rgba(254, 162, 28, 0.6);\n"
                                              "    color: rgb(238, 243, 243);\n"
                                              "    font: 18pt \"Al Bayan\";\n"
                                              "}\n"
                                              "QPushButton:hover{\n"
                                              "    background-color: rgba(254, 162, 28, 0.7);\n"
                                              "}\n"
                                              "QPushButton:pressed{\n"
                                              "    background-color: rgba(254, 162, 28, 0.8);\n"
                                              "}\n"
                                              "QPushButton:disabled{\n"
                                              "    background-color: rgb(159, 159, 159);\n"
                                              "}")
        self.start_PortScan_btn.setObjectName("start_PortScan_btn")
        self.label_11 = QtWidgets.QLabel(self.tab_3)
        self.label_11.setGeometry(QtCore.QRect(30, 70, 81, 21))
        self.label_11.setStyleSheet("color: rgb(255, 255, 255);\n"
                                    "font: 18pt \"Al Bayan\";")
        self.label_11.setObjectName("label_11")
        self.label_12 = QtWidgets.QLabel(self.tab_3)
        self.label_12.setGeometry(QtCore.QRect(300, 70, 81, 21))
        self.label_12.setStyleSheet("color: rgb(255, 255, 255);\n"
                                    "font: 18pt \"Al Bayan\";")
        self.label_12.setObjectName("label_12")
        self.clear_PortScan_btn = QtWidgets.QPushButton(self.tab_3)
        self.clear_PortScan_btn.setGeometry(QtCore.QRect(680, 60, 121, 31))
        self.clear_PortScan_btn.setStyleSheet("QPushButton{\n"
                                              "    color: rgb(238, 243, 243);\n"
                                              "    font: 18pt \"Al Bayan\";\n"
                                              "    border: 1px solid white;\n"
                                              "    border-radius: 10px;\n"
                                              "}\n"
                                              "QPushButton:hover{\n"
                                              "    background-color: rgba(254, 162, 28, 0.7);\n"
                                              "}\n"
                                              "QPushButton:pressed{\n"
                                              "    background-color: rgba(254, 162, 28, 0.8);\n"
                                              "}")
        self.clear_PortScan_btn.setObjectName("clear_PortScan_btn")
        self.label_13 = QtWidgets.QLabel(self.tab_3)
        self.label_13.setGeometry(QtCore.QRect(570, 20, 81, 21))
        self.label_13.setStyleSheet("color: rgb(255, 255, 255);\n"
                                    "font: 18pt \"Al Bayan\";")
        self.label_13.setObjectName("label_13")
        self.PortScan_com = QtWidgets.QComboBox(self.tab_3)
        self.PortScan_com.setGeometry(QtCore.QRect(670, 20, 131, 21))
        self.PortScan_com.setObjectName("PortScan_com")
        self.PortScan_com.addItem("")
        self.PortScan_com.addItem("")
        self.PortScan_com.addItem("")
        self.PortScan_com.addItem("")
        self.PortScan_com.addItem("")
        self.PortScan_startPort_lnEd = QtWidgets.QLineEdit(self.tab_3)
        self.PortScan_startPort_lnEd.setGeometry(QtCore.QRect(130, 70, 141, 21))
        self.PortScan_startPort_lnEd.setStyleSheet("background-color: rgba(255,255,255,0.2);\n"
                                                   "color: rgb(255, 255, 255);\n"
                                                   "border: 1px solid white;\n"
                                                   "border-radius: 10px;")
        self.PortScan_startPort_lnEd.setObjectName("PortScan_startPort_lnEd")
        self.PortScan_endPort_lnEd = QtWidgets.QLineEdit(self.tab_3)
        self.PortScan_endPort_lnEd.setGeometry(QtCore.QRect(400, 70, 141, 21))
        self.PortScan_endPort_lnEd.setStyleSheet("background-color: rgba(255,255,255,0.2);\n"
                                                 "color: rgb(255, 255, 255);\n"
                                                 "border: 1px solid white;\n"
                                                 "border-radius: 10px;")
        self.PortScan_endPort_lnEd.setObjectName("PortScan_endPort_lnEd")
        self.PortScan_textBrowser = QtWidgets.QTextBrowser(self.tab_3)
        self.PortScan_textBrowser.setGeometry(QtCore.QRect(20, 160, 791, 361))
        self.PortScan_textBrowser.setStyleSheet("QTextBrowser{\n"
                                                "    color: rgb(37, 238, 36);\n"
                                                "    font: 18pt \"Trebuchet MS\";\n"
                                                "    background-color: rgba(166, 161, 142, 0.6);\n"
                                                "}")
        self.PortScan_textBrowser.setObjectName("PortScan_textBrowser")
        self.tabWidget.addTab(self.tab_3, "")
        self.tab_4 = QtWidgets.QWidget()
        self.tab_4.setStyleSheet("QWidget#tab_4{\n"
                                 "border-image: url(:/background/images/background/webscan.jpg);\n"
                                 "}")
        self.tab_4.setObjectName("tab_4")
        self.label_14 = QtWidgets.QLabel(self.tab_4)
        self.label_14.setGeometry(QtCore.QRect(30, 20, 81, 21))
        self.label_14.setStyleSheet("color: rgb(255, 255, 255);\n"
                                    "font: 18pt \"Al Bayan\";")
        self.label_14.setObjectName("label_14")
        self.ServiceAdd_lnEd = QtWidgets.QLineEdit(self.tab_4)
        self.ServiceAdd_lnEd.setGeometry(QtCore.QRect(130, 20, 431, 21))
        self.ServiceAdd_lnEd.setStyleSheet("background-color: rgba(255,255,255,0.2);\n"
                                           "color: rgb(255, 255, 255);\n"
                                           "border: 1px solid white;\n"
                                           "border-radius: 10px;")
        self.ServiceAdd_lnEd.setObjectName("ServiceAdd_lnEd")
        self.start_ServiceScan_btn = QtWidgets.QPushButton(self.tab_4)
        self.start_ServiceScan_btn.setEnabled(False)
        self.start_ServiceScan_btn.setGeometry(QtCore.QRect(30, 70, 771, 31))
        self.start_ServiceScan_btn.setStyleSheet("QPushButton{\n"
                                                 "    background-color: rgba(254, 162, 28, 0.6);\n"
                                                 "    color: rgb(238, 243, 243);\n"
                                                 "    font: 18pt \"Al Bayan\";\n"
                                                 "}\n"
                                                 "QPushButton:hover{\n"
                                                 "    background-color: rgba(254, 162, 28, 0.7);\n"
                                                 "}\n"
                                                 "QPushButton:pressed{\n"
                                                 "    background-color: rgba(254, 162, 28, 0.8);\n"
                                                 "}\n"
                                                 "QPushButton:disabled{\n"
                                                 "    background-color: rgb(159, 159, 159);\n"
                                                 "}")
        self.start_ServiceScan_btn.setObjectName("start_ServiceScan_btn")
        self.clear_ServiceScan_btn = QtWidgets.QPushButton(self.tab_4)
        self.clear_ServiceScan_btn.setGeometry(QtCore.QRect(680, 20, 121, 31))
        self.clear_ServiceScan_btn.setStyleSheet("QPushButton{\n"
                                                 "    color: rgb(238, 243, 243);\n"
                                                 "    font: 18pt \"Al Bayan\";\n"
                                                 "    border: 1px solid white;\n"
                                                 "    border-radius: 10px;\n"
                                                 "}\n"
                                                 "QPushButton:hover{\n"
                                                 "    background-color: rgba(254, 162, 28, 0.7);\n"
                                                 "}\n"
                                                 "QPushButton:pressed{\n"
                                                 "    background-color: rgba(254, 162, 28, 0.8);\n"
                                                 "}")
        self.clear_ServiceScan_btn.setObjectName("clear_ServiceScan_btn")
        self.ServiceScan_textBrowser = QtWidgets.QTextBrowser(self.tab_4)
        self.ServiceScan_textBrowser.setGeometry(QtCore.QRect(20, 120, 791, 401))
        self.ServiceScan_textBrowser.setStyleSheet("QTextBrowser{\n"
                                                   "    color: rgb(37, 238, 36);\n"
                                                   "    font: 18pt \"Trebuchet MS\";\n"
                                                   "    background-color: rgba(166, 161, 142, 0.6);\n"
                                                   "}")
        self.ServiceScan_textBrowser.setObjectName("ServiceScan_textBrowser")
        self.tabWidget.addTab(self.tab_4, "")
        self.tab_5 = QtWidgets.QWidget()
        self.tab_5.setStyleSheet("QWidget#tab_5{\n"
                                 "border-image: url(:/background/images/background/webscan.jpg);\n"
                                 "}")
        self.tab_5.setObjectName("tab_5")
        self.label_20 = QtWidgets.QLabel(self.tab_5)
        self.label_20.setGeometry(QtCore.QRect(30, 20, 81, 21))
        self.label_20.setStyleSheet("color: rgb(255, 255, 255);\n"
                                    "font: 18pt \"Al Bayan\";")
        self.label_20.setObjectName("label_20")
        self.OSAdd_lnEd = QtWidgets.QLineEdit(self.tab_5)
        self.OSAdd_lnEd.setGeometry(QtCore.QRect(130, 20, 431, 21))
        self.OSAdd_lnEd.setStyleSheet("background-color: rgba(255,255,255,0.2);\n"
                                      "color: rgb(255, 255, 255);\n"
                                      "border: 1px solid white;\n"
                                      "border-radius: 10px;")
        self.OSAdd_lnEd.setObjectName("OSAdd_lnEd")
        self.clear_OSscan_btn = QtWidgets.QPushButton(self.tab_5)
        self.clear_OSscan_btn.setGeometry(QtCore.QRect(680, 20, 121, 31))
        self.clear_OSscan_btn.setStyleSheet("QPushButton{\n"
                                            "    color: rgb(238, 243, 243);\n"
                                            "    font: 18pt \"Al Bayan\";\n"
                                            "    border: 1px solid white;\n"
                                            "    border-radius: 10px;\n"
                                            "}\n"
                                            "QPushButton:hover{\n"
                                            "    background-color: rgba(254, 162, 28, 0.7);\n"
                                            "}\n"
                                            "QPushButton:pressed{\n"
                                            "    background-color: rgba(254, 162, 28, 0.8);\n"
                                            "}")
        self.clear_OSscan_btn.setObjectName("clear_OSscan_btn")
        self.start_OSscan_btn = QtWidgets.QPushButton(self.tab_5)
        self.start_OSscan_btn.setEnabled(False)
        self.start_OSscan_btn.setGeometry(QtCore.QRect(30, 70, 771, 31))
        self.start_OSscan_btn.setStyleSheet("QPushButton{\n"
                                            "    background-color: rgba(254, 162, 28, 0.6);\n"
                                            "    color: rgb(238, 243, 243);\n"
                                            "    font: 18pt \"Al Bayan\";\n"
                                            "}\n"
                                            "QPushButton:hover{\n"
                                            "    background-color: rgba(254, 162, 28, 0.7);\n"
                                            "}\n"
                                            "QPushButton:pressed{\n"
                                            "    background-color: rgba(254, 162, 28, 0.8);\n"
                                            "}\n"
                                            "QPushButton:disabled{\n"
                                            "    background-color: rgb(159, 159, 159);\n"
                                            "}")
        self.start_OSscan_btn.setObjectName("start_OSscan_btn")
        self.OSscan_textBrowser = QtWidgets.QTextBrowser(self.tab_5)
        self.OSscan_textBrowser.setGeometry(QtCore.QRect(20, 120, 791, 401))
        self.OSscan_textBrowser.setStyleSheet("QTextBrowser{\n"
                                              "    font: 18pt \"Trebuchet MS\";\n"
                                              "    color: rgb(37, 238, 36);\n"
                                              "    background-color: rgba(166, 161, 142, 0.6);\n"
                                              "}")
        self.OSscan_textBrowser.setObjectName("OSscan_textBrowser")
        self.tabWidget.addTab(self.tab_5, "")
        self.tab_6 = QtWidgets.QWidget()
        self.tab_6.setStyleSheet("QWidget#tab_6{\n"
                                 "border-image: url(:/background/images/background/webscan.jpg);\n"
                                 "}")
        self.tab_6.setObjectName("tab_6")
        self.label_15 = QtWidgets.QLabel(self.tab_6)
        self.label_15.setGeometry(QtCore.QRect(290, 10, 51, 21))
        self.label_15.setStyleSheet("color: rgb(255, 255, 255);\n"
                                    "font: 18pt \"Al Bayan\";")
        self.label_15.setObjectName("label_15")
        self.label_16 = QtWidgets.QLabel(self.tab_6)
        self.label_16.setGeometry(QtCore.QRect(20, 10, 51, 21))
        self.label_16.setStyleSheet("color: rgb(255, 255, 255);\n"
                                    "font: 18pt \"Al Bayan\";")
        self.label_16.setObjectName("label_16")
        self.label_17 = QtWidgets.QLabel(self.tab_6)
        self.label_17.setGeometry(QtCore.QRect(590, 10, 51, 21))
        self.label_17.setStyleSheet("color: rgb(255, 255, 255);\n"
                                    "font: 18pt \"Al Bayan\";")
        self.label_17.setObjectName("label_17")
        self.ftp_ip_list = QFtp_list(self.tab_6)
        self.ftp_ip_list.setGeometry(QtCore.QRect(20, 40, 241, 301))
        self.ftp_ip_list.setAcceptDrops(True)
        self.ftp_ip_list.setStyleSheet("QListWidget{\n"
                                       "    color: rgb(37, 238, 36);\n"
                                       "    font: 18pt \".AppleSystemUIFont\";\n"
                                       "    background-color: rgba(166, 161, 142, 0.6);\n"
                                       "}")
        self.ftp_ip_list.setDragEnabled(True)
        self.ftp_ip_list.setDragDropMode(QtWidgets.QAbstractItemView.DragDrop)
        self.ftp_ip_list.setObjectName("ftp_ip_list")
        self.ftp_userName_list = QFtp_list(self.tab_6)
        self.ftp_userName_list.setGeometry(QtCore.QRect(290, 40, 251, 301))
        self.ftp_userName_list.setAcceptDrops(True)
        self.ftp_userName_list.setStyleSheet("QListWidget{\n"
                                             "    color: rgb(37, 238, 36);\n"
                                             "    font: 18pt \".AppleSystemUIFont\";\n"
                                             "    background-color: rgba(166, 161, 142, 0.6);\n"
                                             "}")
        self.ftp_userName_list.setDragDropMode(QtWidgets.QAbstractItemView.DropOnly)
        self.ftp_userName_list.setObjectName("ftp_userName_list")
        self.ftp_password_list = QFtp_list(self.tab_6)
        self.ftp_password_list.setGeometry(QtCore.QRect(570, 40, 241, 301))
        self.ftp_password_list.setAcceptDrops(True)
        self.ftp_password_list.setStyleSheet("QListWidget{\n"
                                             "    color: rgb(37, 238, 36);\n"
                                             "    font: 18pt \".AppleSystemUIFont\";\n"
                                             "    background-color: rgba(166, 161, 142, 0.6);\n"
                                             "}")
        self.ftp_password_list.setDragDropMode(QtWidgets.QAbstractItemView.DropOnly)
        self.ftp_password_list.setObjectName("ftp_password_list")
        self.ftp_startScan_btn = QtWidgets.QPushButton(self.tab_6)
        self.ftp_startScan_btn.setEnabled(True)
        self.ftp_startScan_btn.setGeometry(QtCore.QRect(650, 480, 161, 41))
        self.ftp_startScan_btn.setStyleSheet("QPushButton{\n"
                                             "    background-color: rgba(254, 162, 28, 0.6);\n"
                                             "    color: rgb(238, 243, 243);\n"
                                             "    font: 18pt \"Al Bayan\";\n"
                                             "}\n"
                                             "QPushButton:hover{\n"
                                             "    background-color: rgba(254, 162, 28, 0.7);\n"
                                             "}\n"
                                             "QPushButton:pressed{\n"
                                             "    background-color: rgba(254, 162, 28, 0.8);\n"
                                             "}\n"
                                             "")
        self.ftp_startScan_btn.setObjectName("ftp_startScan_btn")
        self.label_18 = QtWidgets.QLabel(self.tab_6)
        self.label_18.setGeometry(QtCore.QRect(20, 480, 121, 41))
        self.label_18.setStyleSheet("color: rgb(255, 255, 255);\n"
                                    "font: 18pt \"Al Bayan\";\n"
                                    "border:1px solid;\n"
                                    "background-color: rgba(255, 255, 255,0.2);")
        self.label_18.setObjectName("label_18")
        self.ftp_curr_Ip_lab = QtWidgets.QLabel(self.tab_6)
        self.ftp_curr_Ip_lab.setGeometry(QtCore.QRect(140, 480, 501, 41))
        self.ftp_curr_Ip_lab.setStyleSheet("color: rgb(255, 255, 255);\n"
                                           "font: 18pt \"Al Bayan\";\n"
                                           "border:1px solid;\n"
                                           "background-color: rgba(255, 255, 255,0.2);")
        self.ftp_curr_Ip_lab.setObjectName("ftp_curr_Ip_lab")
        self.ftp_getIp_toolbtn = QtWidgets.QToolButton(self.tab_6)
        self.ftp_getIp_toolbtn.setGeometry(QtCore.QRect(100, 10, 26, 22))
        self.ftp_getIp_toolbtn.setStyleSheet("QToolButton{\n"
                                             "border-image: url(:/icon/images/icon/get.png);\n"
                                             "}\n"
                                             "\n"
                                             "QToolButton:hover{\n"
                                             "border:1px solid white;\n"
                                             "}")
        self.ftp_getIp_toolbtn.setObjectName("ftp_getIp_toolbtn")
        self.ftp_addIp_toolbtn = QtWidgets.QToolButton(self.tab_6)
        self.ftp_addIp_toolbtn.setGeometry(QtCore.QRect(130, 10, 26, 22))
        self.ftp_addIp_toolbtn.setStyleSheet("QToolButton{\n"
                                             "border-image: url(:/icon/images/icon/add.png);\n"
                                             "}\n"
                                             "QToolButton:hover{\n"
                                             "border:1px solid white;\n"
                                             "}")
        self.ftp_addIp_toolbtn.setObjectName("ftp_addIp_toolbtn")
        self.ftp_addUser_toolbtn = QtWidgets.QToolButton(self.tab_6)
        self.ftp_addUser_toolbtn.setGeometry(QtCore.QRect(410, 10, 26, 22))
        self.ftp_addUser_toolbtn.setStyleSheet("QToolButton{\n"
                                               "border-image: url(:/icon/images/icon/add.png);\n"
                                               "}\n"
                                               "QToolButton:hover{\n"
                                               "border:1px solid white;\n"
                                               "}")
        self.ftp_addUser_toolbtn.setObjectName("ftp_addUser_toolbtn")
        self.ftp_addPass_toolbtn = QtWidgets.QToolButton(self.tab_6)
        self.ftp_addPass_toolbtn.setGeometry(QtCore.QRect(670, 10, 26, 22))
        self.ftp_addPass_toolbtn.setStyleSheet("QToolButton{\n"
                                               "border-image: url(:/icon/images/icon/add.png);\n"
                                               "}\n"
                                               "QToolButton:hover{\n"
                                               "border:1px solid white;\n"
                                               "}")
        self.ftp_addPass_toolbtn.setObjectName("ftp_addPass_toolbtn")
        self.ftp_delIp_toolbtn = QtWidgets.QToolButton(self.tab_6)
        self.ftp_delIp_toolbtn.setGeometry(QtCore.QRect(160, 10, 26, 22))
        self.ftp_delIp_toolbtn.setStyleSheet("QToolButton{\n"
                                             "    border-image: url(:/icon/images/icon/devide.png);\n"
                                             "}\n"
                                             "QToolButton:hover{\n"
                                             "border:3px solid white;\n"
                                             "}")
        self.ftp_delIp_toolbtn.setObjectName("ftp_delIp_toolbtn")
        self.ftp_delUser_toolbtn = QtWidgets.QToolButton(self.tab_6)
        self.ftp_delUser_toolbtn.setGeometry(QtCore.QRect(440, 10, 26, 22))
        self.ftp_delUser_toolbtn.setStyleSheet("QToolButton{\n"
                                               "border-image: url(:/icon/images/icon/devide.png);\n"
                                               "}\n"
                                               "QToolButton:hover{\n"
                                               "border:3px solid white;\n"
                                               "}")
        self.ftp_delUser_toolbtn.setObjectName("ftp_delUser_toolbtn")
        self.ftp_delPass_toolbtn = QtWidgets.QToolButton(self.tab_6)
        self.ftp_delPass_toolbtn.setGeometry(QtCore.QRect(700, 10, 26, 22))
        self.ftp_delPass_toolbtn.setStyleSheet("QToolButton{\n"
                                               "border-image: url(:/icon/images/icon/devide.png);\n"
                                               "}\n"
                                               "QToolButton:hover{\n"
                                               "border:3px solid white;\n"
                                               "}")
        self.ftp_delPass_toolbtn.setObjectName("ftp_delPass_toolbtn")
        self.ftp_selAll_ip_toolbtn = QtWidgets.QToolButton(self.tab_6)
        self.ftp_selAll_ip_toolbtn.setGeometry(QtCore.QRect(200, 10, 26, 22))
        self.ftp_selAll_ip_toolbtn.setStyleSheet("QToolButton{\n"
                                                 "border-image: url(:/icon/images/icon/check.png);\n"
                                                 "}\n"
                                                 "\n"
                                                 "QToolButton:checked{\n"
                                                 "border-image: url(:/icon/images/icon/checked.png);\n"
                                                 "}\n"
                                                 "\n"
                                                 "QToolButton:hover{\n"
                                                 "border:1px solid white;\n"
                                                 "}")
        self.ftp_selAll_ip_toolbtn.setCheckable(True)
        self.ftp_selAll_ip_toolbtn.setObjectName("ftp_selAll_ip_toolbtn")
        self.ftp_invs_ip_toolbtn = QtWidgets.QToolButton(self.tab_6)
        self.ftp_invs_ip_toolbtn.setGeometry(QtCore.QRect(240, 10, 26, 22))
        self.ftp_invs_ip_toolbtn.setStyleSheet("QToolButton{\n"
                                               "border-image: url(:/icon/images/icon/invs_check.png);\n"
                                               "}\n"
                                               "QToolButton:hover{\n"
                                               "border:1px solid white;\n"
                                               "}")
        self.ftp_invs_ip_toolbtn.setObjectName("ftp_invs_ip_toolbtn")
        self.ftp_selAll_username_btn = QtWidgets.QToolButton(self.tab_6)
        self.ftp_selAll_username_btn.setGeometry(QtCore.QRect(480, 10, 26, 22))
        self.ftp_selAll_username_btn.setStyleSheet("QToolButton{\n"
                                                   "border-image: url(:/icon/images/icon/check.png);\n"
                                                   "}\n"
                                                   "\n"
                                                   "QToolButton:checked{\n"
                                                   "border-image: url(:/icon/images/icon/checked.png);\n"
                                                   "}\n"
                                                   "\n"
                                                   "QToolButton:hover{\n"
                                                   "border:1px solid white;\n"
                                                   "}")
        self.ftp_selAll_username_btn.setCheckable(True)
        self.ftp_selAll_username_btn.setObjectName("ftp_selAll_username_btn")
        self.ftp_selAll_password_toolbtn = QtWidgets.QToolButton(self.tab_6)
        self.ftp_selAll_password_toolbtn.setGeometry(QtCore.QRect(740, 10, 26, 22))
        self.ftp_selAll_password_toolbtn.setStyleSheet("QToolButton{\n"
                                                       "border-image: url(:/icon/images/icon/check.png);\n"
                                                       "}\n"
                                                       "\n"
                                                       "QToolButton:checked{\n"
                                                       "border-image: url(:/icon/images/icon/checked.png);\n"
                                                       "}\n"
                                                       "\n"
                                                       "QToolButton:hover{\n"
                                                       "border:1px solid white;\n"
                                                       "}")
        self.ftp_selAll_password_toolbtn.setCheckable(True)
        self.ftp_selAll_password_toolbtn.setObjectName("ftp_selAll_password_toolbtn")
        self.ftp_invs_username_btn = QtWidgets.QToolButton(self.tab_6)
        self.ftp_invs_username_btn.setGeometry(QtCore.QRect(520, 10, 26, 22))
        self.ftp_invs_username_btn.setStyleSheet("QToolButton{\n"
                                                 "border-image: url(:/icon/images/icon/invs_check.png);\n"
                                                 "}\n"
                                                 "QToolButton:hover{\n"
                                                 "border:1px solid white;\n"
                                                 "}")
        self.ftp_invs_username_btn.setObjectName("ftp_invs_username_btn")
        self.ftp_invs_pass_btn = QtWidgets.QToolButton(self.tab_6)
        self.ftp_invs_pass_btn.setGeometry(QtCore.QRect(780, 10, 26, 22))
        self.ftp_invs_pass_btn.setStyleSheet("QToolButton{\n"
                                             "border-image: url(:/icon/images/icon/invs_check.png);\n"
                                             "}\n"
                                             "QToolButton:hover{\n"
                                             "border:1px solid white;\n"
                                             "}")
        self.ftp_invs_pass_btn.setObjectName("ftp_invs_pass_btn")
        self.ftp_textBrowser = QtWidgets.QTextBrowser(self.tab_6)
        self.ftp_textBrowser.setGeometry(QtCore.QRect(20, 380, 791, 91))
        self.ftp_textBrowser.setAcceptDrops(False)
        self.ftp_textBrowser.setStyleSheet("QTextBrowser{\n"
                                           "    color: rgb(37, 238, 36);\n"
                                           "font: 18pt \"Trebuchet MS\";\n"
                                           "    background-color: rgba(166, 161, 142, 0.6);\n"
                                           "}")
        self.ftp_textBrowser.setObjectName("ftp_textBrowser")
        self.label_19 = QtWidgets.QLabel(self.tab_6)
        self.label_19.setGeometry(QtCore.QRect(350, 350, 91, 21))
        self.label_19.setStyleSheet("color: rgb(255, 255, 255);\n"
                                    "font: 18pt \"Al Bayan\";")
        self.label_19.setObjectName("label_19")
        self.tabWidget.addTab(self.tab_6, "")
        self.tab_7 = QtWidgets.QWidget()
        self.tab_7.setStyleSheet("QWidget#tab_7{\n"
                                 "border-image: url(:/background/images/background/webscan.jpg);\n"
                                 "}")
        self.tab_7.setObjectName("tab_7")
        self.label_21 = QtWidgets.QLabel(self.tab_7)
        self.label_21.setGeometry(QtCore.QRect(30, 20, 81, 21))
        self.label_21.setStyleSheet("color: rgb(255, 255, 255);\n"
                                    "font: 18pt \"Al Bayan\";")
        self.label_21.setObjectName("label_21")
        self.SqlInjuAdd_lnEd = QtWidgets.QLineEdit(self.tab_7)
        self.SqlInjuAdd_lnEd.setGeometry(QtCore.QRect(140, 20, 491, 21))
        self.SqlInjuAdd_lnEd.setStyleSheet("background-color: rgba(255,255,255,0.2);\n"
                                           "color: rgb(255, 255, 255);\n"
                                           "border: 1px solid white;\n"
                                           "border-radius: 10px;")
        self.SqlInjuAdd_lnEd.setObjectName("SqlInjuAdd_lnEd")
        self.clear_SqlInjuScan_btn = QtWidgets.QPushButton(self.tab_7)
        self.clear_SqlInjuScan_btn.setGeometry(QtCore.QRect(680, 20, 121, 31))
        self.clear_SqlInjuScan_btn.setStyleSheet("QPushButton{\n"
                                                 "    color: rgb(238, 243, 243);\n"
                                                 "    font: 18pt \"Al Bayan\";\n"
                                                 "    border: 1px solid white;\n"
                                                 "    border-radius: 10px;\n"
                                                 "}\n"
                                                 "QPushButton:hover{\n"
                                                 "    background-color: rgba(254, 162, 28, 0.7);\n"
                                                 "}\n"
                                                 "QPushButton:pressed{\n"
                                                 "    background-color: rgba(254, 162, 28, 0.8);\n"
                                                 "}")
        self.clear_SqlInjuScan_btn.setObjectName("clear_SqlInjuScan_btn")
        self.start_SqlInjuScan_btn = QtWidgets.QPushButton(self.tab_7)
        self.start_SqlInjuScan_btn.setEnabled(False)
        self.start_SqlInjuScan_btn.setGeometry(QtCore.QRect(30, 140, 771, 31))
        self.start_SqlInjuScan_btn.setStyleSheet("QPushButton{\n"
                                                 "    background-color: rgba(254, 162, 28, 0.6);\n"
                                                 "    color: rgb(238, 243, 243);\n"
                                                 "    font: 18pt \"Al Bayan\";\n"
                                                 "}\n"
                                                 "QPushButton:hover{\n"
                                                 "    background-color: rgba(254, 162, 28, 0.7);\n"
                                                 "}\n"
                                                 "QPushButton:pressed{\n"
                                                 "    background-color: rgba(254, 162, 28, 0.8);\n"
                                                 "}\n"
                                                 "QPushButton:disabled{\n"
                                                 "    background-color: rgb(159, 159, 159);\n"
                                                 "}")
        self.start_SqlInjuScan_btn.setObjectName("start_SqlInjuScan_btn")
        self.SqlInjuScan_textBrowser = QtWidgets.QTextBrowser(self.tab_7)
        self.SqlInjuScan_textBrowser.setGeometry(QtCore.QRect(20, 180, 791, 341))
        self.SqlInjuScan_textBrowser.setStyleSheet("QTextBrowser{\n"
                                                   "    color: rgb(37, 238, 36);\n"
                                                   "    font: 18pt \"Trebuchet MS\";\n"
                                                   "    background-color: rgba(166, 161, 142, 0.6);\n"
                                                   "}")
        self.SqlInjuScan_textBrowser.setObjectName("SqlInjuScan_textBrowser")
        self.label_22 = QtWidgets.QLabel(self.tab_7)
        self.label_22.setGeometry(QtCore.QRect(30, 60, 101, 21))
        self.label_22.setStyleSheet("color: rgb(255, 255, 255);\n"
                                    "font: 18pt \"Al Bayan\";")
        self.label_22.setObjectName("label_22")
        self.label_23 = QtWidgets.QLabel(self.tab_7)
        self.label_23.setGeometry(QtCore.QRect(30, 100, 81, 21))
        self.label_23.setStyleSheet("color: rgb(255, 255, 255);\n"
                                    "font: 18pt \"Al Bayan\";")
        self.label_23.setObjectName("label_23")
        self.SqlInjuUserAgent_lnEd = QtWidgets.QLineEdit(self.tab_7)
        self.SqlInjuUserAgent_lnEd.setGeometry(QtCore.QRect(140, 60, 491, 21))
        self.SqlInjuUserAgent_lnEd.setStyleSheet("background-color: rgba(255,255,255,0.2);\n"
                                                 "color: rgb(255, 255, 255);\n"
                                                 "border: 1px solid white;\n"
                                                 "border-radius: 10px;")
        self.SqlInjuUserAgent_lnEd.setObjectName("SqlInjuUserAgent_lnEd")
        self.SqlInjuCookie_lnEd = QtWidgets.QLineEdit(self.tab_7)
        self.SqlInjuCookie_lnEd.setGeometry(QtCore.QRect(140, 100, 491, 21))
        self.SqlInjuCookie_lnEd.setStyleSheet("background-color: rgba(255,255,255,0.2);\n"
                                              "color: rgb(255, 255, 255);\n"
                                              "border: 1px solid white;\n"
                                              "border-radius: 10px;")
        self.SqlInjuCookie_lnEd.setObjectName("SqlInjuCookie_lnEd")
        self.tabWidget.addTab(self.tab_7, "")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 830, 22))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(0)
        self.start_HostScan_btn.clicked.connect(MainWindow.start_HostScan)
        self.hostAdd_lnEd.textChanged['QString'].connect(MainWindow.enable_startHostScan_btn)
        self.clear_HostScan_btn.clicked.connect(MainWindow.clear_hostScan_TestBrowser)
        self.PortAdd_lnEd.textChanged['QString'].connect(MainWindow.enable_startPortScan_btn)
        self.PortScan_startPort_lnEd.textChanged['QString'].connect(MainWindow.enable_startPortScan_btn)
        self.PortScan_endPort_lnEd.textChanged['QString'].connect(MainWindow.enable_startPortScan_btn)
        self.start_PortScan_btn.clicked.connect(MainWindow.start_PortScan)
        self.clear_PortScan_btn.clicked.connect(MainWindow.clear_PortScan_TestBrowser)
        self.clear_ServiceScan_btn.clicked.connect(MainWindow.clear_ServiceScan_TestBrowser)
        self.start_ServiceScan_btn.clicked.connect(MainWindow.start_ServiceScan)
        self.ServiceAdd_lnEd.textChanged['QString'].connect(MainWindow.enable_startServiceScan_btn)
        self.ftp_addIp_toolbtn.clicked.connect(MainWindow.add_ftpIp)
        self.pushButton.clicked.connect(MainWindow.refresh_ip)
        self.ftp_delIp_toolbtn.clicked.connect(MainWindow.del_ftpIp)
        self.ftp_addUser_toolbtn.clicked.connect(MainWindow.add_ftpUserName)
        self.ftp_delUser_toolbtn.clicked.connect(MainWindow.del_ftpUserName)
        self.ftp_addPass_toolbtn.clicked.connect(MainWindow.add_ftpPassword)
        self.ftp_delPass_toolbtn.clicked.connect(MainWindow.del_ftpPassword)
        self.ftp_getIp_toolbtn.clicked.connect(MainWindow.get_ftpIp)
        self.ftp_selAll_ip_toolbtn.clicked['bool'].connect(MainWindow.selAll_ip)
        self.ftp_invs_ip_toolbtn.clicked.connect(MainWindow.invs_ip)
        self.ftp_selAll_username_btn.clicked['bool'].connect(MainWindow.selAll_username)
        self.ftp_invs_username_btn.clicked.connect(MainWindow.invs_username)
        self.ftp_selAll_password_toolbtn.clicked['bool'].connect(MainWindow.selAll_password)
        self.ftp_invs_pass_btn.clicked.connect(MainWindow.invs_password)
        self.ftp_startScan_btn.clicked.connect(MainWindow.start_FtpScan)
        self.OSAdd_lnEd.textChanged['QString'].connect(MainWindow.enable_startOSscan_btn)
        self.clear_OSscan_btn.clicked.connect(MainWindow.clear_OSscan_TestBrowser)
        self.start_OSscan_btn.clicked.connect(MainWindow.start_OSscan)
        self.SqlInjuAdd_lnEd.textChanged['QString'].connect(MainWindow.enable_SqlInjuScan_btn)
        self.start_SqlInjuScan_btn.clicked.connect(MainWindow.start_SqlInjuScan)
        self.clear_SqlInjuScan_btn.clicked.connect(MainWindow.clear_SqlInjuScan_TestBrowser)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.label.setText(_translate("MainWindow", "网  络  扫  描  器"))
        self.label_2.setText(_translate("MainWindow", "院系: 信息工程系"))
        self.label_3.setText(_translate("MainWindow", "专业: 计算机科学与技术"))
        self.label_4.setText(_translate("MainWindow", "作 者: 陈 彦 志"))
        self.label_5.setText(_translate("MainWindow", "学 号: 1651200111"))
        self.label_6.setText(_translate("MainWindow", "指 导 教 师: 姚 罡"))
        self.label_7.setText(_translate("MainWindow", "桂 林 电 子 科 技 大 学 信 息 科 技 学 院"))
        self.pushButton.setText(_translate("MainWindow", "刷新"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("MainWindow", "主页面"))
        self.label_8.setText(_translate("MainWindow", "主机地址"))
        self.start_HostScan_btn.setText(_translate("MainWindow", "请输入正确格式的主机地址"))
        self.clear_HostScan_btn.setText(_translate("MainWindow", "清空"))
        self.label_9.setText(_translate("MainWindow", "探测方法"))
        self.hostScan_com.setItemText(0, _translate("MainWindow", "arp scan"))
        self.hostScan_com.setItemText(1, _translate("MainWindow", "icmp scan"))
        self.hostScan_com.setItemText(2, _translate("MainWindow", "syn_443 scan"))
        self.hostScan_com.setItemText(3, _translate("MainWindow", "ack_80 scan"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("MainWindow", "主机探测"))
        self.label_10.setText(_translate("MainWindow", "主机地址"))
        self.start_PortScan_btn.setText(_translate("MainWindow", "请输入正确格式的主机地址"))
        self.label_11.setText(_translate("MainWindow", "开始端口"))
        self.label_12.setText(_translate("MainWindow", "结束端口"))
        self.clear_PortScan_btn.setText(_translate("MainWindow", "清空"))
        self.label_13.setText(_translate("MainWindow", "探测方法"))
        self.PortScan_com.setItemText(0, _translate("MainWindow", "SYN 扫描"))
        self.PortScan_com.setItemText(1, _translate("MainWindow", "FIN 扫描"))
        self.PortScan_com.setItemText(2, _translate("MainWindow", "NULL 扫描"))
        self.PortScan_com.setItemText(3, _translate("MainWindow", "XMAS 扫描"))
        self.PortScan_com.setItemText(4, _translate("MainWindow", "UDP 扫描"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_3), _translate("MainWindow", "端口探测"))
        self.label_14.setText(_translate("MainWindow", "主机地址"))
        self.start_ServiceScan_btn.setText(_translate("MainWindow", "请输入正确格式的主机地址"))
        self.clear_ServiceScan_btn.setText(_translate("MainWindow", "清空"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_4), _translate("MainWindow", "服务识别"))
        self.label_20.setText(_translate("MainWindow", "主机地址"))
        self.clear_OSscan_btn.setText(_translate("MainWindow", "清空"))
        self.start_OSscan_btn.setText(_translate("MainWindow", "请输入正确格式的主机地址"))
        self.OSscan_textBrowser.setHtml(_translate("MainWindow",
                                                   "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                                   "<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
                                                   "p, li { white-space: pre-wrap; }\n"
                                                   "</style></head><body style=\" font-family:\'Trebuchet MS\'; font-size:18pt; font-weight:400; font-style:normal;\">\n"
                                                   "<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-family:\'Andale Mono\';\"><br /></p></body></html>"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_5), _translate("MainWindow", "操作系统探测"))
        self.label_15.setText(_translate("MainWindow", "用户名"))
        self.label_16.setText(_translate("MainWindow", "ip地址"))
        self.label_17.setText(_translate("MainWindow", "密码"))
        self.ftp_startScan_btn.setText(_translate("MainWindow", "开始扫描"))
        self.label_18.setText(_translate("MainWindow", "正在检测的是:"))
        self.ftp_curr_Ip_lab.setText(_translate("MainWindow", "None"))
        self.ftp_getIp_toolbtn.setToolTip(_translate("MainWindow", "<html><head/><body><p>获取ip</p></body></html>"))
        self.ftp_getIp_toolbtn.setText(_translate("MainWindow", "..."))
        self.ftp_addIp_toolbtn.setToolTip(_translate("MainWindow", "<html><head/><body><p>添加ip</p></body></html>"))
        self.ftp_addIp_toolbtn.setText(_translate("MainWindow", "..."))
        self.ftp_addUser_toolbtn.setToolTip(_translate("MainWindow", "<html><head/><body><p>添加用户名</p></body></html>"))
        self.ftp_addUser_toolbtn.setText(_translate("MainWindow", "..."))
        self.ftp_addPass_toolbtn.setToolTip(_translate("MainWindow", "<html><head/><body><p>添加用户名</p></body></html>"))
        self.ftp_addPass_toolbtn.setText(_translate("MainWindow", "..."))
        self.ftp_delIp_toolbtn.setToolTip(_translate("MainWindow", "<html><head/><body><p>删除ip</p></body></html>"))
        self.ftp_delIp_toolbtn.setText(_translate("MainWindow", "..."))
        self.ftp_delUser_toolbtn.setToolTip(_translate("MainWindow", "<html><head/><body><p>删除用户名</p></body></html>"))
        self.ftp_delUser_toolbtn.setText(_translate("MainWindow", "..."))
        self.ftp_delPass_toolbtn.setToolTip(_translate("MainWindow", "<html><head/><body><p>删除用户名</p></body></html>"))
        self.ftp_delPass_toolbtn.setText(_translate("MainWindow", "..."))
        self.ftp_selAll_ip_toolbtn.setToolTip(_translate("MainWindow", "<html><head/><body><p>全选</p></body></html>"))
        self.ftp_selAll_ip_toolbtn.setText(_translate("MainWindow", "..."))
        self.ftp_invs_ip_toolbtn.setToolTip(_translate("MainWindow", "<html><head/><body><p>反选</p></body></html>"))
        self.ftp_invs_ip_toolbtn.setText(_translate("MainWindow", "..."))
        self.ftp_selAll_username_btn.setToolTip(_translate("MainWindow", "<html><head/><body><p>全选</p></body></html>"))
        self.ftp_selAll_username_btn.setText(_translate("MainWindow", "..."))
        self.ftp_selAll_password_toolbtn.setToolTip(
            _translate("MainWindow", "<html><head/><body><p>全选</p></body></html>"))
        self.ftp_selAll_password_toolbtn.setText(_translate("MainWindow", "..."))
        self.ftp_invs_username_btn.setToolTip(_translate("MainWindow", "<html><head/><body><p>反选</p></body></html>"))
        self.ftp_invs_username_btn.setText(_translate("MainWindow", "..."))
        self.ftp_invs_pass_btn.setToolTip(_translate("MainWindow", "<html><head/><body><p>反选</p></body></html>"))
        self.ftp_invs_pass_btn.setText(_translate("MainWindow", "..."))
        self.label_19.setText(_translate("MainWindow", "已爆破主机"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_6), _translate("MainWindow", "FTP弱口令检测"))
        self.label_21.setText(_translate("MainWindow", "网址url"))
        self.clear_SqlInjuScan_btn.setText(_translate("MainWindow", "清空"))
        self.start_SqlInjuScan_btn.setText(_translate("MainWindow", "请输入正确格式的主机地址"))
        self.label_22.setText(_translate("MainWindow", "User-Agent"))
        self.label_23.setText(_translate("MainWindow", "Cookie"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_7), _translate("MainWindow", "SQL注入检测"))


from . import res_rc

if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
