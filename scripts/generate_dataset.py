import argparse
import sys
import os
import random 
import subprocess
import logging
import shutil
from pcap2csv import pcap2csv
from revise import revise
from analysis import analysis
from rewrite import rewrite
from generate_labels import init_index, parse_condition, extract_packets
from map_labels import mapping
from reorder import reorder, timestamp_to_num, write_to_file
from portmap import portmap, portrewrite
import split

def get_label(lst, num):
    ret = 0
    for k, _, start, end in lst:
        if num >= start and num < end:
            if k == "attack":
                ret = 1
            elif k == "infection":
                ret = 2
            elif k == "reconnaissance":
                ret = 3
    return ret

def revise_all(flst, prefix, local, ipaddr):
    ret1 = {}
    ret2 = {}
    ret3 = {}
    lens = []       # length of each file
    shifts = [0]    # shift of each file
    random.seed(a=None)
    klst = ["base", "benign", "reconnaissance", "infection", "attack"]
    cwd = os.getcwd()

    rlst = []
    for k in klst:
        if k not in flst:
            rlst.append(k)

    for r in rlst:
        klst.remove(r)

    for k in klst:
        ret1[k] = []
        ret2[k] = []
        ret3[k] = []

    # change the pcap files to the csv files first
    for k in klst:
        for (f, s, d) in flst[k]:
            fname = f
            name, ext = fname.strip().split("/")[-1].split(".")
            if "pcap" not in ext:
                continue
            cname1 = "{}/{}.csv".format(cwd, name)
            if os.path.exists(cname1):
                os.remove(cname1)
            logging.debug("{} is going to be changed into {}".format(name, cname1))
            pcap2csv(fname, cname1)
            pmap = portmap(k, fname, cname1)
            rname = portrewrite(fname, pmap)
            rname = "{}/{}".format(cwd, rname)
            cname2 = rname.replace(".pcap", ".csv")
            pcap2csv(rname, cname2)

            print ("check rname: {} and cname2: {}".format(rname, cname2))
            logging.debug("{} is changed into {}".format(name, cname2))

            start_time = 0
            times = 0
            
            t2n = {}
            n2t = {}
            with open(cname2, "r") as f:
                for line in f:
                    tmp = line.strip().split("|")
                    n = int(tmp[0])
                    t = float(tmp[1])
                    t2n[t] = n
                    n2t[n] = t
                npackets = int(line.split("|")[0])
                times = float(line.split("|")[1])
                logging.debug("{}: {} ({})".format(rname, npackets, times))

            if d >= times:
                start_time = 0
                end_time = start_time + times
                start_number = 1
                end_number = npackets
            else:
                tlst = sorted(list(t2n.keys()))
                number = 0
                for ts in tlst:
                    if ts > times - d:
                        number = t2n[ts]
                        break
                start_number = random.randint(1, number - 1)
                start_time = n2t[start_number]
                ets = start_time + d

                end_number = npackets
                end_time = times
                for ts in reversed(tlst):
                    if ts <= ets:
                        end_number = t2n[ts]
                        end_time = ts
                        break

            logging.debug("{}: start_time: {}, end_time: {}".format(name, start_time, end_time))
            logging.debug("{}: start_number: {}, end_number: {}".format(name, start_number, end_number))
            tname1 = "{}_tmp1.pcap".format(name)
            cmd = ["editcap", "-r", "-v", rname, tname1, "{}-{}".format(start_number, end_number)]
            logging.debug("tname1: {}, cmd: {}".format(tname1, cmd))
            subprocess.call(cmd)
            ret1[k].append(tname1)
            os.remove(rname)
            if len(lens) > 0:
                lens.append((k, name, lens[-1][-1] + 1, lens[-1][-1] + end_number - start_number + 1))
            else:
                lens.append((k, name, 1, end_number - start_number + 1))
            logging.debug("{}: {}-{} -> {}".format(name, start_time, end_time, tname1))
    logging.info("All the pcap files are changed to the csv files")
    print("All the pcap files are changed to the csv files")

    # merge files
    plabelname1 = "{}_label1.pcap".format(prefix)
    cmd = ["mergecap", "-a", "-w", plabelname1]
    for k in klst:
        for elem in ret1[k]:
            cmd.append(elem)
    logging.debug("cmd: {}".format(cmd))
    subprocess.call(cmd)
    clabelname1 = "{}_label1.csv".format(prefix)
    pcap2csv(plabelname1, clabelname1)
    if local:
        maps = analysis(clabelname1)
    else:
        amap = split.split(clabelname1, ipaddr)
        if not amap:
            logging.error("Split is failed")
            print ("Split is failed")
            sys.exit(1)
        maps = analysis(clabelname1, amap)
    logging.debug("lens: {}".format(lens))
    logging.info("All the pcap files are merged into the one file")
    print("All the pcap files are merged into the one file")

    # calculate the shift values
    idx = 0
    with open(clabelname1, "r") as f:
        for line in f:
            tmp = line.strip().split("|")
            num = int(tmp[0])
            ts = float(tmp[1])
            k, name, start, end = lens[idx]
            shift = 0
            if num == start:
                if k == "base":
                    idx += 1
                    continue
                for f, s, d in flst[k]:
                    if name in f:
                        shift = s - ts
                        shifts.append(shift)
                        idx += 1
                        break
            if idx >= len(lens):
                break
    logging.debug("shifts: {}".format(shifts))
    logging.info("The shift values are calculated")
    print("The shift values are calculated")

    # shift the pcap files
    idx = 0
    for k in klst:
        for elem in ret1[k]:
            shift = shifts[idx]
            tname, ext = elem.split(".")
            name = tname.split("_")[0]
            tname = "{}_tmp2.pcap".format(name)
            cmd = ["editcap", "-t", "{}".format(shift), elem, tname]
            logging.debug(cmd)
            subprocess.call(cmd)
            ret2[k].append(tname)
            os.remove(elem)
            idx += 1
    logging.info("The pcap files are all shifted")
    print("The pcap files are all shifted")

    # merge the shifted files (the resultant file is used to extract labels)
    plabelname2 = "{}_label2.pcap".format(prefix)
    cmd = ["mergecap", "-a", "-w", plabelname2]
    for k in klst:
        for elem in ret2[k]:
            cmd.append(elem)
    subprocess.call(cmd)
    logging.info("The shifted pcap files are merged into the one file")
    print("The shifted pcap files are merged into the one file")

    # revise the addresses of each file
    for k in klst:
        for elem in ret2[k]:
            rname = rewrite(elem, maps)
            ret3[k].append(rname)
            os.remove(elem)
    logging.info("The addresses of each file are revised")
    print("The addresses of each file are revised")

    # merge the rewritten files (the resultant file is used as the training/test set)
    pcapname = "{}.pcap".format(prefix)
    cmd = ["mergecap", "-w", pcapname]
    for k in klst:
        for elem in ret3[k]:
            cmd.append(elem)
    subprocess.call(cmd)
    for k in klst:
        for elem in ret3[k]:
            os.remove(elem)
    logging.info("The set is generated")
    print("The set is generated")

    # make the label file
    clabelname2 = "{}_label2.csv".format(prefix)
    pcap2csv(plabelname2, clabelname2)
    ltname1 = "{}_label1".format(prefix)
    with open(ltname1, "w") as of:
        with open(clabelname2, "r") as f:
            for line in f:
                try:
                    tmp = line.strip().split("|")
                    saddr, sport = tmp[4].split(":")
                    daddr, dport = tmp[5].split(":")

                    num = int(tmp[0])
                    ts = tmp[1]
                    protocol = tmp[2]
                    label = get_label(lens, num)
                except:
                    continue
                of.write("{}, {}, {}, {}, {}, {}, {}, {}\n".format(num, ts, protocol, saddr, sport, daddr, dport, label))

    ltname2 = "{}_label2".format(prefix)
    mapping(ltname1, ltname2, maps)

    lname = "{}.label".format(prefix)
    labels = reorder(ltname2)
    csvname = "{}.csv".format(prefix)
    pcap2csv(pcapname, csvname)
    maps = timestamp_to_num(csvname)
    write_to_file(lname, maps, labels)
    logging.info("The label file is generated")
    print ("The label file is generated")

    # make the info file
    iname = "{}.info".format(prefix)
    with open(iname, "w") as of:
        cnt = 0
        with open(clabelname2, "r") as f:
            for line in f:
                cnt = cnt + 1
            of.write("Total Packets: {}\n".format(cnt))

        total = 0
        for b, s, d in flst["base"]:
            total += d
        of.write("Total Time: {}\n".format(total))

        with open(lname, "r") as f:
            try:
                attack_start = False
                infection_start = False
                reconnaissance_start = False
                acnt = 0
                icnt = 0
                rcnt = 0

                for line in f:
                    tmp = line.strip().split(", ")
                    label = int(tmp[-1])
                    if label == 1:
                        acnt += 1
                    elif label == 2:
                        icnt += 1
                    elif label == 3:
                        rcnt += 1

                of.write("Attack Packets: {}\n".format(acnt))
                of.write("Infection Packets: {}\n".format(icnt))
                of.write("Reconnaissance Packets: {}\n".format(rcnt))
            except:
                of.write("Error happened while making the information file")

    if not local:

        cmd = ["tshark", "-r", pcapname, "-Y", "\"ip.src=={} or frame.number==1\"".format(ipaddr[0]), "-w", "{}_0.pcap".format(prefix)]
        subprocess.call(cmd)

        cmd = ["tshark", "-r", pcapname, "-Y", "\"ip.src=={} or frame.number==1\"".format(ipaddr[1]), "-w", "{}_1.pcap".format(prefix)]
        subprocess.call(cmd)

        logging.info("The set is split into the two files")
        print ("The set is split into the two files")

    logging.info("All the tasks are completed")
    print("All the tasks are completed")

    # remove unnecessary files
    os.remove(plabelname1)
    os.remove(plabelname2)
    os.remove(ltname1)
    os.remove(ltname2)
    csvfiles = [ f for f in os.listdir(".") if ".csv" in f]
    for csvfile in csvfiles:
        os.remove(csvfile)

    logging.info("Unnecessary files are deleted")
    print("Unnecessary files are deleted")

    logging.info("The script is quitted")
    print("The script is quitted")

def organize_files(attacks, benigns, infections, reconnaissance):
    flst = {}
    flst["base"] = []

    base = None
    maxd = -1
    for [fname, s, d] in benigns:
        duration = float(d)
        if duration > maxd:
            base = [fname, s, d]
            maxd = duration
    flst["base"].append((os.path.abspath(base[0]), float(base[1]), float(base[2])))
    benigns.remove(base)

    if len(benigns) > 0:
        flst["benign"] = []
        for [fname, s, d] in benigns:
            flst["benign"].append((os.path.abspath(fname), float(s), float(d)))
        logging.debug("benign lst: {}".format(flst["benign"]))

    if reconnaissance:
        flst["reconnaissance"] = []
        for [fname, s, d] in reconnaissance:
            flst["reconnaissance"].append((os.path.abspath(fname), float(s), float(d)))
        logging.debug("reconnaissance lst: {}".format(flst["reconnaissance"]))

    if infections:
        flst["infection"] = []
        for [fname, s, d] in infections:
            flst["infection"].append((os.path.abspath(fname), float(s), float(d)))
        logging.debug("infection lst: {}".format(flst["infection"]))

    if attacks:
        flst["attack"] = []
        for [fname, s, d] in attacks:
            flst["attack"].append((os.path.abspath(fname), float(s), float(d)))
        logging.debug("attack lst: {}".format(flst["attack"]))

    return flst

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--attack", metavar="<attack file list (file name, start time, duration) or (file name, # of packets)>", nargs='+', help="attack file list", type=str, action='append')
    parser.add_argument("-b", "--benign", metavar="<benign file list (file name, start time, duration) or (file name, # of packets)>", nargs='+', help="file list", required=True, type=str, action='append')
    parser.add_argument("-i", "--infection", metavar="<infection file list (file name, start time, duration) or (file name, # of packets)>", nargs='+', help="file list", type=str, action='append')
    parser.add_argument("-r", "--reconnaissance", metavar="<reconnaissance file list (file name, start time, duration) or (file name, # of packets)>", nargs='+', help="file list", type=str, action='append')
    parser.add_argument("-x", "--ipaddr0", metavar="<ip address of dev #0>", help="IP address of Dev #0", type=str)
    parser.add_argument("-y", "--ipaddr1", metavar="<ip address of dev #1>", help="IP address of Dev #1", type=str)
    parser.add_argument("-z", "--local", help="Dataset for the experiment in the local network", action='store_true', default=False)
    parser.add_argument("-p", "--prefix", metavar="<output prefix>",
            help="output prefix", required=True)
    parser.add_argument("-l", "--log", metavar="<log level>",
            help="log level", default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()

    logging.basicConfig(filename="script.log", level=args.log)
    prefix = args.prefix
    ofname = "{}.pcap".format(prefix)
    lname = "{}.label".format(prefix)
    
    with open("cmd.{}".format(prefix), "w") as cf:
        cf.write("python3")
        for arg in sys.argv:
            cf.write(" {}".format(arg))
        cf.write("\n")

    if os.path.exists(ofname):
        logging.error("output pcap file {} already exist".format(ofname))
        sys.exit(1)

    if os.path.exists(lname):
        logging.error("output label file {} already exist".format(lname))
        sys.exit(1)

    if not args.local:
        if not args.ipaddr0 or not args.ipaddr1:
            logging.error("should specify the ip address of the devices")
            sys.exit(1)

    flst = organize_files(args.attack, args.benign, args.infection, args.reconnaissance)
    ipaddr = {}
    ipaddr[0] = args.ipaddr0
    ipaddr[1] = args.ipaddr1
    revise_all(flst, prefix, args.local, ipaddr)

if __name__ == "__main__":
    main()
