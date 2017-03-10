"""
Docker Logger application to automatically scanner running Docker containers and attach to the found
containers to capture the printed logs and upload to a central location. The logger also listens to
Docker events to automatically attach to late started containers and upload the logs to the same
configured central location.
"""
import docker
import sys
import logging
import datetime

from dateutil.parser import parse
from docker_logger.adapter import adapter_factory
from threading import Thread


class DockerLogCapture(Thread):
    """
    Given a container the LogCapture will attach to the container and get all the printed logs. The
    collected logs will be uploaded to the configured central location

    :param container: The container that is to be monitored for logs
    :param adapter: The adapter that is to be used to upload the captured logs

    :type container: docker.models.containers.Container
    :type adapter: docker_logger.adapter.Adapter
    """

    def __init__(self, container, adapter):
        super(DockerLogCapture, self).__init__()

        if not container:
            raise ValueError("Container must be specified and cannot be None")

        if not adapter:
            raise ValueError("Adapter must be specified and cannot be None")

        self._log = logging.getLogger(__name__)
        self._container = container
        self._adapter = adapter
        self._buffer = []

    def run(self):

        try:

            self._log.debug(
                "Starting Docker log capture for container {}".format(self._container.name)
            )

            start_from = parse("2017-03-09T12:42:20.338139139Z")

            for line in self._container.logs(
                    stdout=True, stderr=True, stream=True, timestamps=True,
                    since=start_from.replace(tzinfo=None)):
                self._print_log(line)

        except KeyboardInterrupt:
            self._log.debug(
                "Shutting Docker log capture for container {}".format(self._container.name)
            )

        finally:
            self._log.debug(
                "Docker log capture for container {} stopped".format(self._container.name)
            )

    # function to print the logs being printed from a running container. The function currently
    # only prints the captured logs to the stdout but this can easily be converted to work with
    # the AWS CloudWatch APIs
    def _print_log(self, message):

        is_last_message_incomplete = message[-1:] != "\n"

        # split the stream into individual lines, removing any empty lines but first append any
        # previous messages that are in the buffer
        log_lines = "{previous_message}{new_message}".format(
            previous_message=self._buffer if self._buffer else "",
            new_message=message if is_last_message_incomplete else message[:-1]
        ).split("\n")

        # if the last log entry is not complete keep it in the buffer for the next iteration
        # of the log print
        if is_last_message_incomplete:
            self._buffer = log_lines[-1]
            del log_lines[-1]
        else:
            self._buffer = None

        for log_line in log_lines:
            self._adapter.process_logs([{
                "date": datetime.datetime.now(),
                "message": log_line
            }])


def attach_logger(container, adapter_config):
    """
    Takes a container and starts a logger against it to capture logs and send them to a centralised
    location. The location that will be used by the logger to send the logs is determined by the
    passed adapter configurations.

    :param container: The container for which logs are to be captured
    :param adapter_config: The configuration that should be used to start an adapter to send logs to

    :type container: docker.models.containers.Container
    :type adapter_config: dict
    """
    if container is None:
        raise ValueError("Container must be specified and cannot be None")

    if adapter_config is None:
        raise ValueError("Adapter configuration must be specified and cannot be None")

    # create the adapter that should be used by the log capture
    config = dict(adapter_config)
    config.update({
        "container_id": container.id,
        "container_name": container.name
    })

    adapter = adapter_factory(config)

    logger = DockerLogCapture(container, adapter)
    logger.setName("Docker Log Capture - {}".format(container.name))
    logger.setDaemon(True)
    logger.start()


def main():

    logging.basicConfig(level=logging.DEBUG)
    log = logging.getLogger("docker_logger")

    adapter_config = {
        "type": "console"
    }

    log.info("Application startup")

    try:

        # create a connection to the docker instance. This will connect to the instance according to
        # the set docker environment variables. If no variables are provided the connection will be
        # created to a local instance of docker else a remote instance will be connected to
        # according to the configured variables.
        client = docker.from_env()

        # get the list of currently running containers and start the log capture
        for container in client.containers.list(filters={"status": "running"}):
            attach_logger(container, adapter_config)

        # listen to the events from Docker to start the log capture for any started container
        for event in client.events(decode=True):
            if event["Type"] == "container" and event["Action"] == "start":
                attach_logger(client.containers.get(event["id"]), adapter_config)

    except KeyboardInterrupt:
        log.info("Application shutdown requested")

    finally:
        log.info("Application shutdown")


# start the application
if __name__ == "__main__":
    sys.exit(main())
