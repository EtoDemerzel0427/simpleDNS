#!/usr/bin/python
# coding:utf-8
from argparse import ArgumentParser, FileType, ArgumentDefaultsHelpFormatter
from .dnsrelay import *


def add_args():
    """
    add arguments from command-line.

    :return: args

    """

    parser = ArgumentParser("dnsdelay",
                            formatter_class=ArgumentDefaultsHelpFormatter,
                            conflict_handler='resolve')

    parser.add_argument("-d", dest="debug1",
                        action="store_true", default=False,
                        help="The first level debug info.")

    parser.add_argument("-dd", dest="debug2",
                        action="store_true", default=False,
                        help="The second level debug info.")

    parser.add_argument("-autosave", dest="autosave",
                        action="store_true", default=False,
                        help="automatic save to file.")

    parser.add_argument("--server_ip", dest="server_ip",
                        default="202.106.0.20",
                        help="The ip address of the dns server.")

    parser.add_argument("--config", dest="config",
                        default="zones.json",
                        help="The local config file.")

    return parser.parse_args()




if __name__ == '__main__':
    args = add_args()
    print("The configuration of our DNS relay is as below:")
    print("Server-ip: ", args.server_ip)
    print("Config-file: ", args.config)
    print("First level debug info: ", args.debug1)
    print("Second level debug info: ", args.debug2)
    print("Autosave:", args.autosave)

    dns = DnsRelay(debug1=args.debug1, debug2=args.debug2, server_ip=args.server_ip, config_file=args.config, autosave=args.autosave)
    dns.handle_request()