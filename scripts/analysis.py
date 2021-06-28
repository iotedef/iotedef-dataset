import argparse
import os.path
import sys
import ipaddress

def analysis(cname, amap=None):
    used_ports = {}
    used_ports[23] = 23
    used_ports[80] = 80
    used_ports[443] = 443
    loopback = "127.0.0.1"
    internal = "127.0.0.1"
    external = "127.1.0.1"

    used_addr = {}

    addr = int(ipaddress.IPv4Address(loopback))
    iaddr = int(ipaddress.IPv4Address(internal))
    eaddr = int(ipaddress.IPv4Address(external))

    mapping = {}
    port = 7001

    with open(cname, "r") as f:
        for line in f:
            try:
                tmp = line.strip().split("|")
                protocol = tmp[2]
                sender = tmp[4]
                receiver = tmp[5]

                if sender not in mapping:
                    tmp = sender.split(":")
                    saddr = tmp[0]
                    sport = int(tmp[1])

                    if amap:
                        mapping[sender] = "{}:{}".format(amap[saddr], sport)
                    else:   
                        if saddr in used_addr:
                            mapping[sender] = "{}:{}".format(used_addr[saddr], sport)
                        else:
                            mapping[sender] = "{}:{}".format(str(ipaddress.IPv4Address(addr)), sport)
                            used_addr[saddr] = str(ipaddress.IPv4Address(addr))
                            addr = addr + 1

                if receiver not in mapping:
                    tmp = receiver.split(":")
                    daddr = tmp[0]
                    dport = int(tmp[1])

                    if amap:
                        mapping[receiver] = "{}:{}".format(amap[daddr], dport)
                    else:
                        if daddr in used_addr:
                            mapping[receiver] = "{}:{}".format(used_addr[daddr], dport)
                        else:
                            mapping[receiver] = "{}:{}".format(str(ipaddress.IPv4Address(addr)), dport)
                            used_addr[daddr] = str(ipaddress.IPv4Address(addr))
                            addr = addr + 1

            except:
                continue

#    write_mapping(mapping)
    return mapping

def write_mapping(mapping):
    of = open("mapping", "w")

    for k in mapping:
        line = "{}, {}\n".format(k, mapping[k])
        of.write(line)

    of.close()

def command_line_args():
    """Helper called from main() to parse the command line arguments"""

    parser = argparse.ArgumentParser()
    parser.add_argument('--csv', metavar='<input csv file>',
                        help='csv file to create', required=True)
    args = parser.parse_args()
    return args

def main():
    """Program main entry"""
    args = command_line_args()

    if not os.path.exists(args.csv):
        print('Output csv file "{}" not exists, '.format(args.csv),
              file=sys.stderr)
        sys.exit(-1)

    mapping = analysis(args.csv)
    write_mapping(mapping)

if __name__ == '__main__':
    main()
