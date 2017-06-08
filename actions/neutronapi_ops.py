#!/usr/bin/env python
# neutronapi_ops.py: implements action as per BootStack Action ideas ->
#
# Given an IP address, get a bunch of troubleshooting info on the IP, e.g.
# - if it's a host, the hostname
# - if an instance, the host it's on and various namespace info
# - if a floating, what it's associated with,
# - if a router, the uuid/name and tenant, etc
#
from __future__ import print_function
import itertools
import sys

from cliff import app
from cliff import commandmanager
from cliff.lister import Lister

from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client as ks_client
from neutronclient.v2_0 import client as neutron_client
from oslo_config import cfg
# import logging

CONF = None
KS_SESSION = None

# logging.basicConfig()


def _CONF_init():
    global CONF

    nova_opts = [
        cfg.StrOpt('region_name',),
        cfg.StrOpt('endpoint_type',),
    ]
    keystone_authtoken_ops = [
        cfg.StrOpt('auth_url',),
        cfg.StrOpt('username',),
        cfg.StrOpt('password',),
        cfg.StrOpt('project_name',),
        cfg.StrOpt('project_domain_name',),
        cfg.StrOpt('user_domain_name',),
    ]
    CONF = cfg.ConfigOpts()
    CONF(['--config-file', '/etc/neutron/neutron.conf'])
    CONF.register_opts(keystone_authtoken_ops, group='keystone_authtoken')
    CONF.register_opts(nova_opts, group='nova')


def _get_keystone_session():
    global KS_SESSION

    if not KS_SESSION:
        auth = v3.Password(
            auth_url='{}/v3'.format(CONF.keystone_authtoken.auth_url),
            username=CONF.keystone_authtoken.username,
            password=CONF.keystone_authtoken.password,
            user_domain_name=CONF.keystone_authtoken.user_domain_name,
            project_domain_name=CONF.keystone_authtoken.project_domain_name,
            project_name=CONF.keystone_authtoken.project_name,
        )
        KS_SESSION = session.Session(auth=auth, verify=False)

    return KS_SESSION


def get_keystone_client():
    sess = _get_keystone_session()
    return ks_client.Client(session=sess)


def get_neutron_client():
    sess = _get_keystone_session()
    return neutron_client.Client(session=sess,
                                 region_name=CONF.nova.region_name)


class NeutronApiOps(app.App):

    def __init__(self):
        super(NeutronApiOps, self).__init__(
            description='neutron ops helper',
            version='0.1',
            command_manager=commandmanager.CommandManager('neutronapiops'),
            deferred_help=True,
        )

    def _info_ports(self, args):
        ip_ports = []
        for port in self.nc.list_ports()["ports"]:
            for fixed_ip in port["fixed_ips"]:
                if args.ip == fixed_ip["ip_address"]:
                    extra = fixed_ip
                    extra.update({"network_id": port["network_id"]})
                    ip_ports.append([port["id"], extra])
        return ((args.ip, 'neutron', 'port', port[0], port[1])
                for port in ip_ports)

    # XXX stub: needs implementation
    def _info_nodes(self, args):
        return

    def get_ip_info(self, args):
        # Need to filter the generators passed to itertools.chain()
        # for not None-s
        args = [gen for gen in (self._info_ports(args),
                                self._info_nodes(args))
                if gen]
        return itertools.chain(*args)

    def initialize_app(self, argv):
        # self.LOG.debug('initialize_app')
        _CONF_init()
        self.commands = {"get-ip-info": GetIPInfo}
        for k, v in self.commands.items():
            self.command_manager.add_command(k, v)
        self.nc = get_neutron_client()

    def prepare_to_run_command(self, cmd):
        # self.LOG.debug('prepare_to_run_command %s', cmd.__class__.__name__)
        pass

    def clean_up(self, cmd, result, err):
        # self.LOG.debug('clean_up %s', cmd.__class__.__name__)
        if err:
            self.LOG.error('ERROR: %s', err)


class GetIPInfo(Lister):
    "Get IP Information from various possible places"

    def get_parser(self, prog_name):
        parser = super(GetIPInfo, self).get_parser(prog_name)
        parser.add_argument('ip')
        return parser

    def take_action(self, parsed_args):
        return(('IP', 'service', 'type', 'uuid', 'extra'),
               self.app.get_ip_info(parsed_args))


def main(argv=sys.argv[1:]):
    myapp = NeutronApiOps()
    return myapp.run(argv)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
