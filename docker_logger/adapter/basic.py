"""
Basic adapters that can be used to log captured messages from containers
"""
from __future__ import print_function
from docker_logger.adapter import Adapter


class ConsoleAdapter(Adapter):
    """
    An adapter to write captured logs to console (stdout). This mainly can be used for testing
    purposes
    """

    def __init__(self, config):
        super(ConsoleAdapter, self).__init__(config)

    def process_logs(self, logs=list()):

        # if no logs have been specified move on, no need to panic
        if not logs:
            return

        # print the given logs to console
        for log in logs:
            print(
                "{container_name}: {date} - {message}".format(
                    container_name=self._config.get("container_name", "Unknown"),
                    date=log["date"],
                    message=log["message"]
                )
            )
