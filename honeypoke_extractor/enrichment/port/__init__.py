from honeypoke_extractor.enrichment.base import PortEnrichmentProvider

class PortRoleIdentifier(PortEnrichmentProvider):

    def __init__(self):
        self._matched_items = {}
        self._ports = {}

    def on_port(self, protocol, port):
        port_roles = []

        if protocol == "tcp":
            if port in (80, 81, 8080, 8888, 443, 8000, 8090, 8088, 8443, 8081, 8082, 8089, 8118, 9000):
                port_roles.append("web")
            elif port in (3389, 5900, 5901, 6000, 6001):
                port_roles.append("remote-gui")
            elif port in (
                22, 2222, # SSH
                23, 2323, # Telnet
                512, 513, # Rlogin/rsh
                5555, # Android Debug Bridge (ADB)
                5985, 5986, # Microsoft Remote Management
                623, # IPMI
                ):
                port_roles.append("remote-cli")
            elif port in (
                88, 4444, # Kerberos
                389, 636, # LDAP
                ):
                port_roles.append("auth")
            elif port in (
                21, 20, 989, 990, # FTP 
                445, # SMB
                137, 138, 139 # NetBIOS
                ):
                port_roles.append("files")
            elif port in (
                25, 2525, 587, 465, #SMTP
                110, 995, # POP3
                109, # POP2
                143, 993 # IMAP
                ):
                port_roles.append("email")
            elif port in (
                2375, 2376, 4243, # Docker
                2377,# Docker Swarm
                6443, 10250, 10259, 10257 # Kubernetes
                ):
                port_roles.append("container")

            if port in (135, 111, 445):
                port_roles.append("rpc")
            elif port in (
                514, # Syslog
                161, 162, # SNMP
                8291, # MikroTik
                902, 903, # ESXi
                ):
                port_roles.append("admin")
            elif port in (53, 5353):
                port_roles.append("dns")
            elif port in (
                1433, # SQL Server
                5432, # Postgres
                3306, # MySql
                9200, 9300, # ElasticSearch
                27017, 27018, 27019, 28017, # MongoDB
                6379, # Redis
                ):
                port_roles.append("db")
            elif port in (
                5269, # Jabber
                194, # IRC
                5060, # SIP
                ):
                port_roles.append("comms")
            elif port in (
                2601, # Zebra/Quagga
                179, # BGP
                ):
                port_roles.append("routing")
            elif port in (
                43, # Whois
                79, # BGP
                ):
                port_roles.append("info")
            elif port in (
                502, # ModBus
                ):
                port_roles.append("devcomms")

            if port in (
                4444, # Metasploit
                7547, # TP-Link remote
                8291, # MikroTik
                ):
                port_roles.append("exploit")
            elif port in (8118, ):
                port_roles.append("proxy")
        elif protocol == "udp":
            if port in (88, 389):
                port_roles.append("auth")
            elif port in (
                137, 138, 139, # NetBIOS
                69 # TFTP
                ):
                port_roles.append("files")
            elif port in (
                43, # Whois
                79, # BGP
                1900, # UPnP
                ):
                port_roles.append("info")
            elif port in (514, 161, 162, 123):
                port_roles.append("admin")
            elif port in (53, 5353):
                port_roles.append("dns")
            elif port in (623,):
                port_roles.append("remote-cli")
            elif port in (
                500, # IPSec
                1194, # OpenVPN
            ):
                port_roles.append("vpn")

            if port in (111, 135):
                port_roles.append("rpc")
            elif port in (
                5060, # SIP
                ):
                port_roles.append("comms")
            elif port in (
                520, # RIP
                3784, 3785, 4784, # BGP
                ):
                port_roles.append("routing")

        return port_roles
    
    def on_item(self, item):
        port = item['port']
        protocol = item['protocol']
        port_str_id = f"{protocol}/{port}"

        
        self._ports[port_str_id] = self.on_port(protocol, port)
        
        item['roles'] = self._ports[port_str_id]
        
    def get_results(self):
        
        return {
            "ports": self._ports,
            "items": self._matched_items
        }
