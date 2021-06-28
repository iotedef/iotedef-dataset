import argparse
import os
import subprocess
import sys

def make_command(addr_chain, port_chain, pcap, ofname):
    args = []

    cmd = "tcprewrite"
    args.append(cmd)

    dmac = "--enet-dmac=00:00:00:00:00:00"
    args.append(dmac)

    smac = "--enet-smac=00:00:00:00:00:00"
    args.append(smac)

    src_ip_map = "--srcipmap={}".format(addr_chain)
    args.append(src_ip_map)

    dst_ip_map = "--dstipmap={}".format(addr_chain)
    args.append(dst_ip_map)

    port_map = "--portmap={}".format(port_chain)
    args.append(port_map)

    infile = "--infile={}".format(pcap)
    args.append(infile)

    outfile = "--outfile={}".format(ofname)
    args.append(outfile)

    return args

def rewrite(pcap, mapping):
    ofname = "{}_revised.pcap".format(pcap.split(".")[0])
    addr_chain = None
    port_chain = None

    num = 0
    for k in mapping:
        try:
            tmp1, tmp2 = k, mapping[k]
            addr_before, port_before = tmp1.split(":")
            addr_after, port_after = tmp2.split(":")

        #print ("addr_before: {}, port_before: {}, addr_after: {}, port_after: {}".format(addr_before, port_before, addr_after, port_after))

            if addr_chain:
                if "{}:{}".format(addr_before, addr_after) not in addr_chain:
                    addr_chain = addr_chain + ",{}:{}".format(addr_before, addr_after)
            else:
                addr_chain = "{}:{}".format(addr_before, addr_after)

            if port_chain:
                if "{}:{}".format(port_before, port_after) not in port_chain:
                    port_chain = port_chain + ",{}:{}".format(port_before, port_after)
            else:
                port_chain = "{}:{}".format(port_before, port_after)

            num = num + 1

#            if num >= 10:
#                args = make_command(addr_chain, port_chain, pcap, ofname)
#                print ("Command: {}".format(args))
#                ret = subprocess.call(args)
                #print ("Return of {}: {}".format(args, ret))

#                num = 0
#                addr_chain = None
#                port_chain = None
        except:
            pass

        if addr_chain and port_chain:
            args = make_command(addr_chain, port_chain, pcap, ofname)
            #print ("Command: {}".format(args))
            ret = subprocess.call(args)
        #print ("Return of {}: {}".format(args, ret))

    return ofname

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', metavar='<input pcap file>',
                        help='pcap file to parse', required=True)
    parser.add_argument('--mapping', metavar='<mapping file>',
                        help='mapping to apply', required=True)
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()

    if not os.path.exists(args.pcap):
        print('Input pcap file "{}" does not exist'.format(args.pcap),
              file=sys.stderr)
        sys.exit(-1)

    if not os.path.exists(args.mapping):
        print('Output csv file "{}" does not exist'.format(args.mapping),
              file=sys.stderr)
        sys.exit(-1)

    rewrite(args.pcap, args.mapping)

if __name__ == '__main__':
    main()
