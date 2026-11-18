# SPDX-License-Identifier: MIT OR Apache-2.0

"""
Background polling of an Electrum server, for tests
"""

import threading


class Poller(threading.Thread):
    """Poll get_history every `interval` seconds and keep the last length."""

    def __init__(self, client, sh, interval):
        super().__init__(daemon=True)
        self.client, self.sh, self.interval = client, sh, interval
        self.length = None
        self.polls = 0
        self.error = None
        self.stop = threading.Event()

    def run(self):
        try:
            while not self.stop.is_set():
                self.length = len(self.client.get_history(self.sh))
                self.polls += 1
                self.stop.wait(self.interval)
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.error = error
        finally:
            if self.client.is_connected:
                self.client.conn.close()
