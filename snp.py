import argparse, socket, json, requests, ipaddress, subprocess, os
from ipwhois import IPWhois
from pprint import pprint

def main(ip, p, ipi, ar, b, t, sp, ep, op, cv): 
    if args.ip and args.p:
        socket_obj = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = socket_obj.connect_ex((args.ip,args.p))
        socket_obj.close()
        if result == 0:
            machine_hostname = socket.gethostbyaddr(args.ip)[0]
            service = socket.getservbyport(args.p)
            print('--------------------  Ports - Services  --------------------')
            print("Open Port on: " + str(args.ip) + " \n-- Open Port: " + str(args.p) + " \n-- Service Name: " + str(service) + " \n-- Hostname: " + str(machine_hostname))
            print('------------------------------------------------------------\n')
        else:
            return None
    if args.op:
        try:
            open_ports = []
            for port in range(sp, ep):
                open_port = scanport(op, port)
                if open_port is None:
                    continue
                else:
                    open_ports.append(open_port)
            return open_ports
        except:
            pass
    elif args.ipi:
        ip_addr = socket.gethostbyname(ipi)
        headers = {
            'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'
        }
        fields = (
            ("Status", "status"),
            ("Continent", "continent"),
            ("Continent Code", "continentCode"),
            ("Country", "country"),
            ("Country Code", "countryCode"),
            ("Region", "region"),
            ("Region Name", "regionName"),
            ("City", "city"),
            ("District", "district"),
            ("Zipcode", "zip"),
            ("Latitude", "lat"),
            ("Longitude", "lon"),
            ("Timezone", "timezone"),
            ("Currency", "currency"),
            ("ISP", "isp"),
            ("Organization", "org"),
            ("AS", "as"),
            ("AS Name", "asname"),
            ("Reverse DNS", "reverse"),
            ("Mobile", "mobile"),
            ("Proxy", "proxy"),
            ("Hosting", "hosting"),
            ("IP", "query"),
        )
        req = requests.get(f'http://ip-api.com/json/{ip_addr}?fields={",".join([key for _, key in fields])}', headers=headers).json()
        final_formatting = "\n".join([f"{title}: {{{key}}}" for title, key in fields]).format(**req)
        print(final_formatting)
    elif args.ar:
        with open(os.devnull, "wb") as limbo:
            net4 = ipaddress.ip_network(f'{args.nd}/24')
            for ip in net4.hosts():
                res = subprocess.Popen(["ping", "-n", "1", "-w", "200", str(ip)], stdout=limbo, stderr=limbo).wait()
                if res:
                    pass
                else:
                    print(f'LIVE: {str(ip)}')
    elif args.b:
        for port in range(sp, ep):
            try:
                print(f'Getting banner information for port: {port}')
                s = socket.socket()
                s.connect((args.b, port))
                banner = s.recv(1024)
                print(f"{args.b}: {banner}")
            except:
                print(f'Cannot connect to port: {port}')
    elif args.b and args.cv:
        vulnerabilities_list = [
            '3Com 3CDaemon FTP Server Version 2.0'
            'Ability Server 2.34'
            'CCProxy Telnet Service Ready'
            'ESMTP TABS Mail Server for Windows NT'
            'FreeFloat Ftp Server (Version 1.00)'
            'IMAP4rev1 MDaemon 9.6.4 ready'
            'MailEnable Service, Version: 0-1.54'
            'NetDecision-HTTP-Server 1.0'
            'PSO Proxy 0.9'
            'SAMBAR  Sami FTP Server 2.0.2'
            'Spipe 1.0'
            'TelSrv 1.5'
            'WDaemon 6.8.5'
            'WinGate 6.1.1'
            'Xitami'
            'YahooPOPs! Simple Mail Transfer Service Ready'
        ]
        for line in vulnerabilities_list:
            line = line.strip('\n')
            if banner in line:
                print(f'{banner} is vulnerable')
    elif args.t:
        obj = IPWhois(f'{str(t)}')
        res = obj.lookup_rdap(depth=1)
        pprint(res)
    else:
        print('Invalid argument was used!')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Slim's Network Mapper v1.0")
    ap = argparse.ArgumentParser(prog='smap.py', usage='')# usage='%(prog)s [options] -ipi ip to grab information on')
    ap.add_argument('-ip', type=str, help='Input IP address to check for a single open port')
    ap.add_argument('-p', type=str, help='Input single port to check if it is open')
    ap.add_argument('-op', type=str, help='Input IP Address to check for multiple open ports')
    ap.add_argument('-ipi', type=str, help='Input IP address to get information on')
    ap.add_argument('-ar', type=str, help='Input IP address (192.165.0.1, 192.165.1.0) to get all live ips in that range')
    ap.add_argument('-b', type=str, help='Scan all open ports for banners from services')
    ap.add_argument('-cv', type=str , help='Check service for vulnerabilities')
    ap.add_argument('-t', type=str, help='IPWhois lookup on IP address')
    ap.add_argument('-sp', type=int, help='Starting port')
    ap.add_argument('-ep', type=int, help='End port')
    args = ap.parse_args()
    ip = args.ip
    p = args.p
    op = args.op
    ipi = args.ipi
    ar = args.ar
    b = args.b
    t = args.t
    sp = args.sp
    ep = args.ep
    cv = args.cv
    main(ip, p, ipi, ar, b, t, sp, ep, op, cv)
