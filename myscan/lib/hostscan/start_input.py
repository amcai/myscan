from myscan.lib.hostscan.input_sour.from_nmap_text_import import get_data_from_textfile
from myscan.lib.hostscan.input_sour.from_json_import import get_data_from_jsonfile

from myscan.lib.core.data import cmd_line_options, logger
from myscan.lib.core.common import getredis
import traceback, json


def start_input():
    if cmd_line_options.command == "hostscan":
        try:
            red = getredis()
            if cmd_line_options.input_nmaptext:
                datas = get_data_from_textfile(cmd_line_options.input_nmaptext)
                logger.info("input {} lines from nmap_text".format(len(datas)))
                for data in datas:
                    red.lpush("hostdata", json.dumps(data))
            if cmd_line_options.input_jsonfile:
                datas = get_data_from_jsonfile(cmd_line_options.input_jsonfile)
                logger.info("input {} lines from nmap_json".format(len(datas)))
                for data in datas:
                    red.lpush("hostdata", json.dumps(data))
        except Exception as ex:
            traceback.print_exc()
            logger.warning("input target to hostdata get error:{}".format(ex))
