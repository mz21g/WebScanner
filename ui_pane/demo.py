try:
    orig_url = self.__ui.SqlInjuAdd_lnEd.text()
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

    self.__ui.statusbar.showMessage("正在检测 " + orig_url + " 请稍等~")
    self.__ui.statusbar.clearMessage()
    print("正在探测", orig_url, "请稍等~")
    self.__ui.SqlInjuScan_textBrowser.append(
        "<font color='#ffe7d1'>" + "正在扫描请稍等>>>>>" + "</font><br/><br/>")
    t1 = time.time()

    for payload in payload_dict:

        url = parse_url + str(id_val) + payload + remain

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
    self.__ui.SqlInjuScan_textBrowser.append("<font color='#25ee24'>" + e + "</font><br/>")
    t2 = time.time()
    run_time = t2 - t1
    print('共计用时: ', round(run_time, 2))
    self.__ui.SqlInjuScan_textBrowser.append("<br/><font color='#ffe7d1'>" + "----------共计用时: " + str(
        round(run_time, 2)) + " s--------------" + "</font><br/><br/>")
    pass