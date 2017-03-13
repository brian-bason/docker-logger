"""
Docker Logger application to automatically scanner running Docker containers and attach to the found
containers to capture the printed logs and upload to a central location. The logger also listens to
Docker events to automatically attach to late started containers and upload the logs to the same
configured central location.
"""
import docker
import re
import logging
import sys

from docker_logger.adapter import adapter_factory
from dateutil.parser import parse
from threading import Thread, Timer


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
        self._log_date_regex_matcher = re.compile(
            r"(\d{4}(?:-\d{2}){2}T\d{2}(?::\d{2}){2}\.\d{9}[A-Z])+\s"
        )
        self._logs_flush_timer = None
        self._logs_stream_buffer = ""

    def run(self):

        try:

            self._log.debug(
                "Starting Docker log capture for container '{}'".format(self._container.name)
            )

            start_from = parse("2017-03-09T12:42:20.338139139Z")

            for line in self._container.logs(
                    stdout=True, stderr=True, stream=True, timestamps=True,
                    since=start_from.replace(tzinfo=None)):

                # cancel any log flush if there is anything running
                self._cancel_log_flush()

                # process any captured characters from the stream
                self._process_log_stream(chars=line)

                # start a new log flush cycle
                self._trigger_log_flush()

        except KeyboardInterrupt:
            self._log.debug(
                "Shutting Docker log capture for container '{}'".format(self._container.name)
            )

        finally:

            # make sure that all the messages in the stream has been processed
            self._cancel_log_flush()
            self._process_log_stream(flush=True)

            self._log.debug(
                "Docker log capture for container '{}' stopped".format(self._container.name)
            )

    def _cancel_log_flush(self):
        if self._logs_flush_timer:
            self._logs_flush_timer.cancel()
            self._logs_flush_timer = None

    def _trigger_log_flush(self):
        if not self._logs_flush_timer:
            self._logs_flush_timer = Timer(0.2, self._process_log_stream, kwargs={"flush": True})
            self._logs_flush_timer.start()

    def _process_log_stream(self, chars="", flush=False):
        """
        Processes the incoming characters from the container stream. The characters will first be
        appended to a buffer since they might be coming in small chunks and then the buffer is
        scanned to extract each message
        """

        # append the last received characters to the buffer
        self._logs_stream_buffer += chars

        # find the log dates to determine where each log starts and where it ends
        log_start_pos = [
            (match.start(0), match.group(1))
            for match in self._log_date_regex_matcher.finditer(self._logs_stream_buffer)
        ]

        # keep track of the index in the buffer of the last processed log. This will later help to
        # clear the buffer from processed logs
        next_log_start_pos = 0

        # flush indicates that all the buffer should be emptied, that is the last log in the buffer
        # will be considered complete. If the flush flag is false, then the last message could not
        # be considered complete so the last log will not be processed and left for further
        # character appends processing
        for index, log_message in enumerate(log_start_pos[:-1 if not flush else None]):

            # determine if it is the last log (this can only occur during a flush operation)
            is_last_entry = len(log_start_pos) - 1 == index
            next_log_start_pos = \
                log_start_pos[index + 1][0] if not is_last_entry else len(self._logs_stream_buffer)

            # if it is not the last log record read the characters until the next log start pos else
            # if it is the last log entry read to the end of the buffer and consider it as a
            # complete log. Pass the log entry to the adapter to be consumed
            self._adapter.consume_log(
                date=parse(log_message[1]),
                message=self._logs_stream_buffer[
                    log_message[0] + len(log_message[1]) + 1:next_log_start_pos - 1
                ]
            )

        # clear the buffer from all the processed logs
        self._logs_stream_buffer = self._logs_stream_buffer[next_log_start_pos:]


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
