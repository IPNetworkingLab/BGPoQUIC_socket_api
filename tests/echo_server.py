#!/usr/bin/env python3

import argparse
import asyncio
import functools
import json
import operator
from typing import Dict, Optional

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived
from aioquic.quic.logger import QuicLogger
from aioquic.tls import SessionTicket

__DEFAULT_LISTEN = ["127.0.0.1", "::1"]


class EchoBackProtocol(QuicConnectionProtocol):
    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, StreamDataReceived):
            # send back the client payload
            self._quic.send_stream_data(event.stream_id, event.data)


class SessionTicketStore:
    """
    Simple in-memory store for session tickets.
    """

    def __init__(self) -> None:
        self.tickets: Dict[bytes, SessionTicket] = {}

    def add(self, ticket: SessionTicket) -> None:
        self.tickets[ticket.ticket] = ticket

    def pop(self, label: bytes) -> Optional[SessionTicket]:
        return self.tickets.pop(label, None)


async def main(hosts: list[str],
               port: int,
               quic_configuration: QuicConfiguration,
               session_ticket: SessionTicketStore,
               create_protocol=EchoBackProtocol,
               retry=True) -> None:
    for host in hosts:
        await serve(
            host,
            port,
            configuration=quic_configuration,
            create_protocol=create_protocol,
            session_ticket_fetcher=session_ticket.pop,
            session_ticket_handler=session_ticket.add,
            retry=retry,
        )

    await asyncio.Future()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Simple echo QUIC server")

    parser.add_argument('-p', '--port', dest='port', default=9876, type=int,
                        help='Listen to the specified port (default:9876)')
    parser.add_argument('-l', '--listen', dest='hosts',
                        action='append', nargs=1, type=str,
                        help='listen on the specified addresses (default: 127.0.0.1 and ::1)')
    parser.add_argument('-k', '--key', dest='key', required=True,
                        help='Private key of the server')
    parser.add_argument('-c', '--cert', dest='cert', required=True, type=str,
                        help="Server certificate file")
    parser.add_argument('-a', '--alpn', dest='alpn', required=False, default='echo-server',
                        type=str, help='alpn string used by the server (default: echo-server)')

    args = parser.parse_args()

    if args.hosts is None:
        a_hosts = __DEFAULT_LISTEN
    else:
        a_hosts = functools.reduce(operator.iconcat, args.hosts, [])

    secrets = open('/tmp/keys.tls', 'a')

    configuration = QuicConfiguration(
        alpn_protocols=[args.alpn],
        is_client=False,
        quic_logger=None,
        secrets_log_file=secrets,
        # verify_mode=ssl.CERT_NONE
    )

    configuration.load_cert_chain(args.cert, args.key)
    ticket_store = SessionTicketStore()

    try:
        asyncio.run(
            main(hosts=a_hosts,
                 port=args.port,
                 quic_configuration=configuration,
                 session_ticket=ticket_store)
        )
    except KeyboardInterrupt:
        exit(0)
    finally:
        secrets.close()
