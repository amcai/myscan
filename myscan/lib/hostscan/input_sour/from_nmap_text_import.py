import re


def get_data_from_textfile(filename):
    datas = []
    with open(filename,errors="ignore") as f:
        texts = f.read()
        hostsdata = re.findall(
            '(scan report.*?)Nmap', texts, re.S
        )
        for host in hostsdata:
            ip = ''
            for line in host.split('\n'):
                if 'scan report for' in line:
                    ip = line.split(' ')[3]
                elif '/tcp' in line or '/udp' in line:
                    linesplit = re.split('\s+', line)
                    try:
                        port, service, version = linesplit[0], linesplit[2], ' '.join(linesplit[3:])
                        p,t=port.split("/",1)
                        if re.search(".*?ttl \d{1,4}", version.strip()):
                            version = re.search(".*?ttl \d{1,4}(.*?$)", version.strip()).group(1).strip()
                        datas.append(
                            {
                                "filter": True,
                                "scan": False,
                                "addr": ip,
                                "port": int(p),
                                "type":t,
                                "service": {
                                    service: version
                                }

                            }
                        )

                    except Exception as e:
                        print("process get_data_from_textfile error: {}".format(e))
    return datas

