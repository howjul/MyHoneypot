from warnings import filterwarnings
filterwarnings(action='ignore', module='.*paramiko.*') # 忽略 paramiko 模块的警告
filterwarnings(action='ignore', module='.*socket.*') # 忽略 socket 模块的警告

from paramiko import RSAKey, ServerInterface, Transport, OPEN_SUCCEEDED, AUTH_SUCCESSFUL, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED, OPEN_SUCCEEDED, AUTH_FAILED
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, getfqdn
from _thread import start_new_thread
from io import StringIO
from random import choice
from helper import server_arguments, set_local_vars, setup_logger
from uuid import uuid4
from contextlib import suppress
from re import compile as rcompile
from time import time
from threading import Event


class QSSHServer():
    def __init__(self, **kwargs):
        # 随机选择一个字符串作为 SSH 服务器的版本，以模拟真实的 SSH 服务器环境
        self.mocking_server = choice(['OpenSSH 7.5', 'OpenSSH 7.3', 'Serv-U SSH Server 15.1.1.108', 'OpenSSH 6.4']) 
        # 生成一个唯一标识符，用于日志记录或其他跟踪用途
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8] 

        # 获取配置信息
        self.config = kwargs.get('config', '')

        if self.config:
            self.logs = setup_logger(__class__.__name__, self.uuid, self.config) # 为当前类创建一个日志记录器
            set_local_vars(self, self.config) # 为当前类设置本地变量
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None) 
        
        # 设置类的属性
        # - 首先尝试从关键字参数 kwargs 中获取对应的值
        # - 如果关键字参数中没有提供，将检查类实例是否已经有这些属性。如果有，则使用已存在的值
        # - 如果以上两种方式都没有提供值，将使用默认值
        self.ip = kwargs.get('ip', None) or (hasattr(self, 'ip') and self.ip) or '127.0.0.1'
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 22
        self.username = kwargs.get('username', None) or (hasattr(self, 'username') and self.username) or 'zhz'
        self.password = kwargs.get('password', None) or (hasattr(self, 'password') and self.password) or 'zhz'
        self.ansi = rcompile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]') # 匹配 ANSI 转义序列的正则表达式

        print(f'ip: {self.ip}; port: {self.port}; username: {self.username}; password: {self.password}')

    def generate_pub_pri_keys(self):
        with suppress(Exception):
            key = RSAKey.generate(2048)
            string_io = StringIO()
            key.write_private_key(string_io)
            return key.get_base64(), string_io.getvalue()
        return None, None

    def ssh_server_main(self):
        _q_s = self

        class SSHHandle(ServerInterface):

            def __init__(self, ip, port):
                self.ip = ip
                self.port = port
                self.event = Event()

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def check_channel_request(self, kind, chanid):
                if kind == 'session':
                    return OPEN_SUCCEEDED
                return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

            # 处理认证请求
            # - 如果凭据与设置的用户名和密码匹配，则返回 AUTH_SUCCESSFUL，否则返回 AUTH_FAILED
            def check_auth_password(self, username, password):
                username = self.check_bytes(username)
                password = self.check_bytes(password)
                status = 'failed'
                if username == _q_s.username and password == _q_s.password:
                    username = _q_s.username
                    password = _q_s.password
                    status = 'success'
                if status == 'success':
                    _q_s.logs.info({'server': 'ssh_server', 'action': 'login', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'username': username, 'password': password})
                    return AUTH_SUCCESSFUL
                _q_s.logs.info({'server': 'ssh_server', 'action': 'login', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'username': username, 'password': password})
                return AUTH_FAILED

            def check_channel_exec_request(self, channel, command):
                if "capture_commands" in _q_s.options:
                    _q_s.logs.info({'server': 'ssh_server', 'action': 'command', 'src_ip': self.ip, 'src_port': self.port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, "data": {"command": self.check_bytes(command)}})
                self.event.set()
                return True

            def get_allowed_auths(self, username):
                return "password,publickey"

            # def check_auth_publickey(self, username, key):
            #     _q_s.logs.info({'server': 'ssh_server', 'action': 'login', 'src_ip': self.ip, 'src_port': self.port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, "username": self.check_bytes(username), 'key_fingerprint': self.check_bytes(hexlify(key.get_fingerprint()))})
            #     return AUTH_SUCCESSFUL

            def check_channel_shell_request(self, channel):
                return True

            def check_channel_direct_tcpip_request(self, chanid, origin, destination):
                return OPEN_SUCCEEDED

            def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
                return True

        def ConnectionHandle(client, priv):
            # 建立 SSH 传输层
            t = Transport(client)
            ip, port = client.getpeername()
            # 记录客户端连接信息
            _q_s.logs.info({'server': 'ssh_server', 'action': 'connection', 'src_ip': ip, 'src_port': port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})
            # 设置模拟的 SSH 服务器版本
            t.local_version = 'SSH-2.0-' + _q_s.mocking_server
            t.set_gss_host(getfqdn(""))
            t.load_server_moduli()
            # 添加服务器的 RSA 密钥
            t.add_server_key(RSAKey(file_obj=StringIO(priv)))
            # 创建 SSHHandle 实例并启动 SSH 服务器
            sshhandle = SSHHandle(ip, port)
            t.start_server(server=sshhandle)
            # 等待客户端认证，超时设置为 30 秒
            conn = t.accept(30)
            # 处理交互式 shell
            if conn is not None:
                # 发送欢迎信息和命令提示符
                conn.send("Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.10.60.1-microsoft-standard-WSL2 x86_64)\r\n\r\n")
                current_time = time()
                while True:
                    conn.send("/$ ")
                    line = ""
                    while not line.endswith("\x0d") and not line.endswith("\x0a"): # and time() < current_time + 10:
                        conn.settimeout(10)
                        recv = conn.recv(1).decode()
                        conn.settimeout(None)
                        if _q_s.ansi.match(recv) is None and recv != "\x7f":
                            conn.send(recv)
                            line += recv
                    line = line.rstrip()
                    # 记录交互式命令
                    _q_s.logs.info({'server': 'ssh_server', 'action': 'interactive', 'src_ip': ip, 'src_port': port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, "data": {"command": line}})
                    # 模拟命令执行结果
                    if line == "ls":
                        conn.send("\r\nbin cdrom etc lib lib64 lost+found mnt proc run snap swapfile tmp var boot dev home lib32 libx32 media opt root sbin srv sys usr\r\n")
                    elif line == "pwd":
                        conn.send("\r\n/\r\n")
                    elif line == "whoami":
                        conn.send("\r\nroot\r\n")
                    elif line == "exit":
                        break
                    else:
                        conn.send("\r\n{}: command not found\r\n".format(line))

                # 关闭连接和传输 
                sshhandle.event.wait(2)
                conn.close()
                t.close()

        # 创建一个套接字对象 sock，用于监听来自客户端的连接请求
        sock = socket(AF_INET, SOCK_STREAM) # AF_INET 指的是 IPv4 地址族，而 SOCK_STREAM 表示这是一个 TCP 套接字。
        sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1) # 设置套接字的选项，以允许重新使用同一地址（IP 和端口）
        sock.bind((self.ip, self.port)) # 将套接字绑定到指定的 IP 地址和端口号
        sock.listen(1) # 开始监听连接请求，1即系统允许排队等待接受的未处理连接的最大数量

        # 生成 SSH 连接所需服务器的公钥和私钥
        pub, priv = self.generate_pub_pri_keys() # 生成 SSH 连接所需的公钥和私钥
        # with open('/Users/zhz/.ssh/id_rsa', 'r') as priv_file:
        #     priv = priv_file.read()
        # with open('/Users/zhz/.ssh/id_rsa.pub', 'r') as pub_file:
        #     pub = pub_file.read()

        # 无限循环等待连接，使服务器持续运行并不断等待新的连接请求
        while True:
            # 阻塞等待一个新的客户端连接，返回一个新的套接字对象 client 和连接的客户端地址 addr
            client, addr = sock.accept() 
            print("来自连接", addr)
            #  在一个新的线程中启动 ConnectionHandle 函数，处理这个新的客户端连接
            start_new_thread(ConnectionHandle, (client, priv,))

if __name__ == '__main__':
    # 解析命令行参数
    parsed = server_arguments()
    # 创建 SSH 服务器实例
    qsshserver = QSSHServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, config=parsed.config)
    # 启动 SSH 服务器
    qsshserver.ssh_server_main()