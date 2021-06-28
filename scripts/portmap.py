import argparse
import os.path
import sys
import ipaddress
import logging
import subprocess

def make_command(port_chain, pcap, ofname):
    args = []

    cmd = "tcprewrite"
    args.append(cmd)

    port_map = "--portmap={}".format(port_chain)
    args.append(port_map)

    infile = "--infile={}".format(pcap)
    args.append(infile)

    outfile = "--outfile={}".format(ofname)
    args.append(outfile)

    return args

def portmap(category, pname, cname):
    ret = {}

    logging.info("starting> pname: {}, cname: {}".format(pname, cname))
    with open(cname, "r") as f:
        for line in f:
            try:
                tmp = line.strip().split("|")
                source = tmp[4]
                saddr, sport = source.split(":")
                dest = tmp[5]
                daddr, dport = dest.split(":")

                sport = int(sport) 
                dport = int(dport)

                rsport = sport % 10000
                rdport = dport % 10000

                if category == "attack":
                    ret[sport] = rsport + 10000
                    ret[dport] = rdport + 10000
                elif category == "infection":
                    ret[sport] = rsport + 20000
                    ret[dport] = rdport + 20000
                elif category == "reconnaissance":
                    ret[sport] = rsport + 30000
                    ret[dport] = rdport + 30000
                else:
                    ret[sport] = rsport
                    ret[dport] = rdport
            except:
                continue

    logging.info("finished> ret: {}".format(ret))
    return ret

def portrewrite(pname, pmap):
    rname = "{}_remap.pcap".format(pname.split("/")[-1].split(".")[0])
    port_chain = None

    for k in pmap:
        if port_chain:
            port_chain = port_chain + ",{}:{}".format(k, pmap[k])
        else:
            port_chain = "{}:{}".format(k, pmap[k])

    args = make_command(port_chain, pname, rname)
    subprocess.call(args)

    return rname
    
def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--ipaddr0", metavar="<ip address of dev #0>", help="IP address of Dev #0", type=str, required=True)
    parser.add_argument("-b", "--ipaddr1", metavar="<ip address of dev #1>", help="IP address of Dev #1", type=str, required=True)
    parser.add_argument('--csv', metavar='<input csv file>',
                        help='csv file to create', required=True)
    parser.add_argument("-l", "--log", metavar='<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>',
                        help='Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)', type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()

    logging.basicConfig(level=args.log)
    if not os.path.exists(args.csv):
        logging.error('Output csv file "{}" not exists, '.format(args.csv),
              file=sys.stderr)
        sys.exit(-1)

    ipaddr = {}
    ipaddr[0] = args.ipaddr0
    ipaddr[1] = args.ipaddr1
    ret = split(args.csv, ipaddr)

    for k in ret:
        print ("{}: {}".format(k, ret[k]))

if __name__ == '__main__':
    main()
