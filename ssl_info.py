#!/usr/bin/env python3


import socket
import ssl
import datetime
import click
import logging
from pprint import pprint


cli = click.Group()


def parse_ssl_dns(ssl_info):
    return map(lambda x: x[1], ssl_info['subjectAltName'])


def parse_date(data):
    """
    :data:      date in human-readable format
    :return:    formatted date
    """

    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
    # parse the string from the certificate into a Python datetime object
    return datetime.datetime.strptime(data, ssl_date_fmt)


def get_ssl_info(hostname, server_hostname, ipv6=False, port=443, timeout=3.0):
    """
    :hostname: host to connect to
    :server_hostname: servername ('Host' header)
    :ipv6: use ipv6 to connect to host if True, otherwise use ipv4
    :port: tcp port to connect to
    :timeout: connect timeout
    :return: ssl_info else None
    """
    # set socket address family
    socket_af = socket.AF_INET6 if ipv6 else socket.AF_INET

    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket_af),
        server_hostname=server_hostname,
    )

    conn.settimeout(timeout)

    try:
        conn.connect((hostname, port))
        ssl_info = conn.getpeercert()

        logging.debug('ssl_info: {}'.format(ssl_info))
    except Exception as e:
        logging.debug('hostname: {}'.format(hostname))
        logging.debug('server_hostname: {}'.format(server_hostname))
        logging.debug('ipv6: {}'.format(ipv6))
        logging.debug('port: {}'.format(port))
        logging.debug('timeout: {}'.format(timeout))
        raise(e)

    return ssl_info


def get_domain_info(hostname, server_hostname, ipv6=False, port=443, timeout=3.0):
    """
    return datetime of expiry date
    return example: datetime.datetime(2019, 8, 13, 14, 46, 22)
    :hostname: host to connect to
    :server_hostname: servername ('Host' header)
    :ipv6: use ipv6 to connect to host if True, otherwise use ipv4
    :return: tuple of (expiry date, subjectAltName)
    """

    expiry_date = None
    cert_dns = None

    ssl_info = get_ssl_info(hostname, server_hostname, ipv6=ipv6, port=port, timeout=timeout)

    if ssl_info:
        if isinstance(ssl_info, Exception):
            msg = '{h}: {e}'.format(h=hostname, e=ssl_info)
            click.echo(click.style(msg, fg='red'), err=True)
        else:
            expiry_date = parse_date(ssl_info['notAfter'])
            cert_dns = parse_ssl_dns(ssl_info)

    return (
        expiry_date,
        cert_dns
    )


@cli.command('show-ssl-info')
@click.argument('hostlist', type=str, nargs=-1)
@click.option('--servername', '-s', help='Servername (virtual host) to check.', type=str)
@click.option('--port', '-p', help='Port to connect to.', type=int, default=443)
@click.option('--field', '-f', help='SSL Info field', type=str, default='')
@click.option('--timestamp', '-t', help='Return date in timestamp format (notBefore, notAfter)', is_flag=True, default=False)
@click.option('--timestamp-delta', '-td', help='Return date in timestamp format (notBefore, notAfter)', is_flag=True, default=False)
@click.option('--verbose', '-v', help='Be verbose', is_flag=True, default=False)
@click.option('--debug', '-d', help='Debug messages.', is_flag=True, default=False)
def show_ssl_info(hostlist, servername, port, field, timestamp, timestamp_delta, verbose, debug):
    """
    print ssl info to output
    :hostlist: host list string
    :servername: virtual host
    """

    if debug:
        logging.basicConfig(level=logging.DEBUG)
        print('[D] DEBUG MODE')

    for host in hostlist:
        if verbose:
            click.echo('[.] hostname: {}'.format(servername or host))

        if ':' in host:
            ipv6 = True
        else:
            ipv6 = False

        ssl_info = get_ssl_info(host, servername or host, ipv6=ipv6, port=port, timeout=1.0)
        try:
            if not ssl_info.get('issuer', False):
                print('[.] failed to get ssl info: {}'.format(ssl_info))
        except Exception as e:
            logging.error('failed to get ssl info: {}'.format(e))
            return

        if len(field):
            if field in ['notBefore', 'notAfter']:
                # format date
                date = parse_date(ssl_info.get(field, ''))

                if timestamp:
                    result = date.strftime('%s')
                elif timestamp_delta:
                    result = (date - datetime.datetime.now()).total_seconds()
                else:
                    result = date.strftime('%Y-%m-%d %H:%M:%S')

                print(result)

            else:
                # pretty print field data
                pprint(ssl_info.get(field, ''))

        else:
            # pretty print all data
            pprint(
                get_ssl_info(host, servername or host, ipv6=ipv6, port=port, timeout=1.0)
            )


@cli.command('check-cert')
@click.option('--hosts-file', '-f', help='Read hosts list from file.', type=click.File('r'))
@click.option('--hostlist', '-l', help='Host list separated by comma.', type=str)
@click.option('--servername', '-s', help='Servername (virtual host) to check.', type=str)
@click.option('--days-threshold', '-t', help='Threshold in days.', default=30)
@click.option('--debug', '-d', help='Debug messages.', is_flag=True)
def main(hosts_file, hostlist, servername, days_threshold, debug):
    """
    check expiry date
    :hosts_file: file with hosts list
    :hostlist: host list string
    :servername: virtual host
    :days_threshold: check threshold in days
    :debug: turn debug on
    :return:
    """
    now = datetime.datetime.now()
    hosts = []
    servername_by_host = False if servername else True

    if debug:
        logging.basicConfig(level=logging.DEBUG)

    if hostlist:
        hosts.extend(hostlist.split(','))

    if hosts_file:
        hosts.extend(hosts_file.read().strip().split('\n'))

    for host in hosts:

        host = host.strip().strip('.').strip()

        if servername_by_host:
            servername = host

        logging.debug(click.style('host: {}; servername: {}'.format(host, servername), fg='blue'))

        expiry_date, cert_dns = get_domain_info(host, servername)
        if expiry_date and cert_dns:
            expiry_date_delta = expiry_date - now
            msg = '{host}:  subjectAltName: {cert_dns} will expire in {days} days and {hours} hours ({date}) (server_name: {server_name})'.format(
                host=host, cert_dns=cert_dns, server_name=servername,
                days=expiry_date_delta.days, hours=expiry_date_delta.seconds/3600,
                date=expiry_date,
            )

            if expiry_date_delta.days < days_threshold:
                click.echo(click.style(msg, fg='red'))
            else:
                click.echo(click.style(msg, fg='green'))


if __name__ == '__main__':
    #main()
    #show_ssl_info()
    cli()
