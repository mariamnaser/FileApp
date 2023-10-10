import threading
import socket
import time
import argparse
import sys
import os
import random
import pickle

###ERROR STRINGS
Invalid_mode = "Invalid mode, use -s for server or -c for client."
s_req = "Server requires: -s <port>"
c_req = "Client requires: -c <name> <server_ip> <server_port> <udp_port> <tcp_port>"
###Flags
new = 0
ack = 1
##Multi-Mode Variable
# Get the local hostname
hostname = socket.gethostname()
gen_ip = socket.gethostbyname(hostname)
table = []
sent = []
idn = random.randint(0,1000000)
###Server Helpers
name=None
rev_evnt = threading.Event()
clients=[]
cl_table={}
###Client Helpers
udp_evnt = threading.Event()
tcp_evnt = threading.Event()
rqst = threading.Event()
s_add = None
dir = None
reg_in = 0
###Multi-Mode Helper Functions
def port_valid(p):
    return 1024 <= p <= 65535
def ip_valid(ip):
    comp = ip.split('.')
    valid = False
    if len(comp) == 4:
        for i in comp:
            if not i:
                return valid
        valid = True
    return valid
def msg_create(msg_type, sender, iden, msg):
    comp_msg = f"{msg_type}|{sender}|{iden}|{msg}"
    return comp_msg
def parse_message(comp_msg):
    components = comp_msg.split('|')
    if len(components) == 4:
        return tuple(components)
    else:
        return []

def Diff(li1, li2):
    li_dif = [i for i in li1 + li2 if i not in li1 or i not in li2]
    return li_dif
###Server Helper Functions
def snd_tbl(sock):
    global idn
    global table
    global clients
    global cl_table
    global sent
    prv_tbl = []
    clint = []
    i = 1
    while True:
        if not rev_evnt.is_set():
            fl_tbl()
            if len(table) != 0 and i ==1:
                print(table)
                i+=1
            if (prv_tbl != table) and (len(table) != 0):
                prv_tbl = table.copy()
                rows_strings = [' '.join(map(str, file_pro)) for file_pro in table]
                table_string = '\n'.join(rows_strings)
                for client in clients:
                    c = msg_create(new, name, idn, table_string)
                    sent.append(idn)
                    print(f"c: {c}")
                    sock.sendto(c.encode(), client)
                    time.sleep(0.5)
                    for _ in range(2):
                        if len(sent)!=0:
                            print(sent)
                            time.sleep(0.5)
                            sock.sendto(c.encode(), client)
                idn+=1
            elif (clint != clients) and (len(table) != 0):
                rows_strings = [' '.join(map(str, file_pro)) for file_pro in table]
                table_string = '\n'.join(rows_strings)
                if clint == []:
                    newclint = clients
                    clint = clients.copy()
                    print(f"First user {newclint}")
                else:
                    newclint = Diff(clint, clients)
                    print(f"new User {newclint}")
                for client in newclint:
                    c = msg_create(new, name, idn, table_string)
                    sent.append(idn)
                    sock.sendto(c.encode(), client)
                    time.sleep(0.5)
                    for _ in range(2):
                        if len(sent)!=0:
                            print(sent)
                            time.sleep(0.5)
                            sock.sendto(c.encode(), client)
                    if len(sent)!=0:
                        sent.remove(idn-1)
                idn+=1
                clint = clients.copy()

def fl_tbl():
    global cl_table
    global table
    table = []
    ps_tbl = cl_table.copy()
    for name, info in ps_tbl.items():
        files = info.get('filenames', [])
        if files:
            for file in files:
                ip_add = info.get('ip')
                tcp_add = info.get('tcp_port')
                status = info.get('status')
                new_row = [file, name, ip_add, tcp_add, status]
                table.append(new_row)

def server(port):
    global clients
    global cl_table
    global sent
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((gen_ip, port))
    tbl_snd = threading.Thread(target=snd_tbl,args=(sock,),daemon=True)
    tbl_snd.start()
    while True:
        try:
            rev_evnt.clear()
            data, addr = sock.recvfrom(1024)
            if data:
                type, name, mid, msg= parse_message(data.decode())
                if int(type) == new:
                    data = data.decode()
                    rev_evnt.set()
                    if msg.startswith("reg"):
                        data_comp = msg.split(" ")
                        _, name, cl_tcp = data_comp
                        if name not in cl_table:
                            cl_table[name] = {
                                'status': 'active',
                                'ip': addr[0],
                                'tcp_port': cl_tcp,
                                'filenames': []
                            }
                            clients.append(addr)
                            s_msg = "$ >>> [Welcome, You are registered.]"
                        else:
                            if (
                                cl_table[name]['ip'] == addr[0] and
                                cl_table[name]['tcp_port'] == cl_tcp and
                                cl_table[name]['status'] == 'offline'):
                                cl_table[name]['status'] = 'active'
                                if addr not in clients:
                                    clients.append(addr)
                                s_msg = "$ >>> [Welcome, You are registered.]"
                            else:
                                s_msg = "$ >>> Username is already taken"
                                print(cl_table)
                    elif msg.startswith("offer"):
                        s_msg = "$ >>> [Offer Message received by Server.]"
                        if name in cl_table:
                            clnt = cl_table[name]
                            files = msg.strip().split(" ")[1:]
                            clnt['filenames'].extend(files)
                    elif msg.startswith("dereg"):
                        s_msg = "$ >>> [You are Offline. Bye.]"
                        if addr in clients:
                            clients.remove(addr)
                        if name in cl_table:
                            cl_table[name]['status'] = 'offline'
                    ack_msg = msg_create(ack, name, mid, s_msg)
                    sock.sendto(ack_msg.encode(), addr)
                if int(type) == ack:
                    if int(mid) in sent:
                        sent.remove(int(mid))
                        print(f"removed {mid}")
        except KeyboardInterrupt:
            print("\nQuitting...")
            break

###Client Helper Functions
def lstn_tcp(tcp_socket):
    tcp_socket.listen(1)
    while True:
        if not rqst.is_set():
            recv_socket, recv_address = tcp_socket.accept()
            print(f"$ < Accepting connection request from {recv_address[0]} >")
            tcp_evnt.set()
            req = recv_socket.recv(1024).decode()
            req_comp = req.split(" ")
            requested_file_name = req_comp[0]
            file_name = os.path.join(dir,requested_file_name)
            try:
                with open(file_name, 'rb') as file:
                    print(f"$ < Transferring {requested_file_name}... >")
                    data = file.read(1024)
                    while data:
                        recv_socket.send(data)
                        data = file.read(1024)
                print(f"<{requested_file_name} transferred successfully! >")
            except FileNotFoundError:
                print(f"File '{requested_file_name}' not found")
            #LOGIC
            print(f"$ < Connection with client {name} closed. >")
            recv_socket.close()
            tcp_evnt.clear()
def lstn_udp(udp_socket):
    global reg_in
    global table
    global new
    global ack
    while True:
        data, addr = udp_socket.recvfrom(1024)
        if data:
            data = data.decode()
            type, _, mid, msg = parse_message(data)
            if not (tcp_evnt.is_set() or rqst.is_set()):  # Use udp_evnt here, not tcp_evnt
                udp_evnt.set()
                mid=int(mid)
                if mid in sent:
                    if reg_in == 1:
                        reg_in = 0
                        print(f"{msg}")
                        if msg.startswith("$ >>> Username"):
                            pass
                        else:
                            sent.remove(mid)
                    else:
                        print(f"{msg}")
                        sent.remove(mid)
                elif int(type) == new:
                    tmp_table = []
                    tmp = msg.split('\n')
                    for sub in tmp:
                        sub =sub.split(' ')
                        tmp_table.append(sub)
                    if tmp_table != table:
                        table = tmp_table
                        print("$ >>> [Client table updated.]")
                    ack_msg = msg_create(ack, name, mid, "ack")
                    udp_socket.sendto(ack_msg.encode(), addr)
                udp_evnt.clear()
def send(udp_socket, msg):
    global idn
    message = msg_create(new, name, idn, msg)
    sent.append(idn)
    idn +=1
    udp_socket.sendto(message.encode(), s_add)
    time.sleep(0.5)
    for _ in range(2):
        if len(sent)!=0:
            time.sleep(0.5)
            udp_socket.sendto(message.encode(), s_add)
    if len(sent)!=0:
        if msg.startswith("dereg"):
            print("$>>> [Server not responding]")
            print("$>>> [Exiting]")
        if msg.startswith("offer"):
            print("$ >>> [No ACK from Server, please try again later.]")
        else:
            print("$ >>> Failed to reach server")
def register(udp_socket, name, udp, tcp):
    global idn
    global reg_in
    reg_in = 1
    reg_msg = f"reg {name} {tcp}"
    message = msg_create(new, name, idn, reg_msg)
    sent.append(idn)
    idn +=1
    udp_socket.sendto(message.encode(), s_add)
    time.sleep(0.5)
    for _ in range(2):
        if len(sent)!=0 and reg_in == 1:
            time.sleep(0.5)
            udp_socket.sendto(message.encode(), s_add)
        elif len(sent)!=0 and reg_in == 0:
            sys.exit()
    if len(sent)!=0 and reg_in == 1:
        print("$ >>> Failed to reach server")
        sys.exit()
def cl_search(req_file, req_from):
    global table
    for row in table:
        if req_file == row[0] and req_from == row[1] and row[-1] == 'active':
            user_address = (row[2], int(row[3]))
            return user_address
    return False
def client(name, s_ip, s_port,udp,tcp):
    global s_add
    global dir
    global table
    ###sockets
    s_add = (s_ip, s_port)
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    udp_socket.bind((gen_ip, udp))
    tcp_socket.bind((gen_ip, tcp))
    ###threads
    udp_lstn = threading.Thread(target=lstn_udp, args=(udp_socket,), daemon=True)
    tcp_lstn = threading.Thread(target=lstn_tcp, args=(tcp_socket,), daemon=True)
    udp_lstn.start()
    register(udp_socket, name, udp, tcp)
    tcp_lstn.start()
    while True:
        try:
            if not(udp_evnt.is_set() or tcp_evnt.is_set()):
                in_data = input("$ >>> ")
                indata = in_data.strip()
                if in_data.startswith("request"):
                    rqst.set()
                    in_data = in_data.split(" ")
                    if len(in_data) != 3:
                        print("$ < Invalid Request >")
                    else:
                        req_from = in_data[2]
                        req_file = in_data[1]
                        res = cl_search(req_file,req_from)
                        if not res:
                            print("$ < Invalid Request >")
                        else:
                            rq_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            rq_socket.connect(res)
                            print(f"$ < Connection with client {req_from} established. >")
                            rq_socket.send(in_data[1].encode())
                            file_name = in_data[1]
                            file_name_ext = file_name.split(".")[0]
                            ext_file = file_name.split(".")[1]
                            received_file_path = file_name_ext + "_" + req_from + ext_file
                            try:
                                with open(received_file_path, 'wb') as file:
                                    print(f"$ < Downloading {req_file}... >")
                                    data = rq_socket.recv(1024)
                                    while data:
                                        file.write(data)
                                        data = rq_socket.recv(1024)
                                print(f"$ < {req_file} downloaded successfully! >")
                            except:
                                print(f"An error occurred while receiving the file '{req_file}'")
                            print(f"$ < Connection with client {req_from} closed. >")
                            rq_socket.close()
                    rqst.clear()
                elif in_data.startswith("list"):
                    if len(table) == 0:
                        print("$ >>> [No files available for download at the moment.]")
                    else:
                        print("$", end =" ")
                        print ("{:<15} {:<10} {:<15} {:<10} {:<15}".format('FILENAME','OWNER','IP ADRESS','TCP PORT', "STATUS"))
                        #pub_table = PrettyTable(["Files"])
                        for row in table:
                            print("$", end =" ")
                            file, owner, ip_i, t_port, stat= row
                            print ("{:<15} {:<10} {:<15} {:<10} {:<15}".format(f'{file}',f'{owner}',f'{ip_i}',f'{t_port}', f'{stat}'))
                elif in_data.startswith("offer"):
                    sendfiles = []
                    notfiles = []
                    if dir != None:
                        files = in_data.split(" ")[1:]
                        for file in files:
                            if os.path.exists(os.path.join(dir, file)):
                                sendfiles.append(file)
                            else:
                                notfiles.append(file)
                        if len(notfiles)!=0:
                            fl_DNE = " ".join(notfiles)
                            print(f"$ >>> {fl_DNE} don't exist")
                        if len(sendfiles) != 0:
                            msg_cont = f"offer {' '.join(sendfiles)}"
                            send(udp_socket, msg_cont)
                    else:
                        print("$ >>> Please set a shared directory first using 'setdir'")
                elif in_data.startswith("dereg"):
                    send(udp_socket,in_data)
                    sys.exit()
                elif in_data.startswith("setdir"):
                    if dir == None:
                        if len(in_data.split(" ")) != 1:
                            new_dir = in_data.split(" ")[1]
                            if os.path.isdir(new_dir):
                                dir = new_dir
                                print(f"$ >>> [Successfully set <{dir}> as the directory for searching offered files.]")
                            else:
                                print(f"$ >>> [setdir failed: <{new_dir}> does not exist.]")
                        else:
                            print(f"$ >>> Not enought arguments where given")
                    else:
                        print(f"$ >>> Directory has already been set to <{dir}>")
                else:
                    print(f"$ >>> <{in_data}> not supported")
                    #send(udp_socket, in_data)
        except KeyboardInterrupt:
            print("\nQuitting...")
            break

if __name__ == "__main__":
    input_args = sys.argv
    if input_args[1:]:
        mode = input_args[1]
        if mode == '-s':
            if len(input_args) == 3:
                port = int(input_args[2])
                if port_valid(port):
                    name = "Server"
                    server(port)
                else:
                    print(f"{port} is not valid port")
            else:
                print(s_req)
        elif mode == '-c':
            if len(input_args) == 7:
                client_name, s_ip, s_port,udp_port,tcp_port = sys.argv[2:]
                s_port, udp_port, tcp_port = map(int,(s_port, udp_port, tcp_port))
                if ip_valid(s_ip):
                    valid = True
                    for p in (s_port,udp_port,tcp_port):
                        valid = valid and port_valid(p)
                        if valid == False:
                            print(f"{p} is not a valid port")
                    if valid == True:
                        name = client_name
                        client(client_name, s_ip, s_port,udp_port,tcp_port)
                else:
                    print(f"{s_ip} if not valid IP")
            else:
                print(c_req)
        else:
            print(f"{mode} is not supported")
    else:
        print(Invalid_mode)
