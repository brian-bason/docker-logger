"""
The adapters that can be used to send captured log messages to a central location
"""
import abc
import logging

from Queue import Queue, Empty
from importlib import import_module

ADAPTERS = {
    "console": {"module": "docker_logger.adapter.basic", "class": "ConsoleAdapter"}
}


class Adapter(object):
    """
    The interface that should be implemented by the adapters

    :param config: The configuration that should be used to start the adapter

    :type config: dict
    """
    __metaclass__ = abc.ABCMeta

    def __init__(self, config):
        super(Adapter, self).__init__()

        if not config:
            raise ValueError("Configuration must be specified and cannot be None")

        self._log = logging.getLogger(__name__)
        self._config = config
        self._logs_batches = Queue()
        self._logs_batch = _LogsBatch()

    def consume_log(self, date, message):
        """
        Consumes a given log. The log entry will either be consumed immediately or buffered for
        later processing according to the adapter

        :param date: The date in UTC of the log message
        :param message: The log message
        """
        # append the log to the current open logs batch. This is done to group together a number of
        # logs and process them in one go instead of one by one. This doesn't mean that a specific
        # adapter will not want to consume the logs as they are received.
        self._logs_batch.append(date=date, message=message)

        # confirm logs per batch has been reached if so start a new batch
        if self._is_full():
            # move the current batch to the logs batches so that it can be processed by the
            # adapter
            self._logs_batches.put(self._logs_batch)
            self._logs_batch = _LogsBatch()

        # confirm if the logs batch should be processed immediately or left for later processing
        if self._should_process():
            self._process()

    def _is_full(self):
        """
        Determine if the logs batch is full and should be closed for further log entries appends.
        Overwrite this method to implement a specific behaviour for an adapter.

        :return: True if and only if the logs batch is full and no further logs could be appended,
            False otherwise.
        """
        return True

    def _should_process(self):
        """
        Determines if the logs batches should be processed now or left for later. Overwrite this
        method to implement a specific behaviour for an adapter

        :return: True if and only if the logs batches should be processed now, False otherwise

        :rtype: bool
        """
        return True

    def _process(self):
        """
        Process the logs batches that are currently in memory. Any logs batches will be processed in
        the order that they have been appended to the buffer
        """
        # process all the logs batches that are in memory. Multiple batches might be in memory if
        # any of the previous processing process failed for some reason
        while not self._logs_batches.empty():
            try:
                # process the logs batches in the order that they have been appended
                logs_batch = self._logs_batches.get()
                self._process_logs_batch(logs_batch)
                # TODO mark the batch as processed
                self._logs_batches.task_done()
            except Empty:
                # there are no more items to be processed
                pass
            except Exception as ex:
                # if any issue occurs don't worry, keep calm and try later
                self._log.error(
                    "Unable to process logs through adapter '{}' due to error '{}'".format(
                        self.__class__.__name__,
                        ex
                    )
                )
                break

    @abc.abstractmethod
    def _process_logs_batch(self, logs_batch):
        """
        Process a particular logs batch. Overwrite this method with a specific implementation for
        the adapter

        :param logs_batch: The logs batch that is to be processed

        :type logs_batch: _LogsBatch
        """
        raise NotImplementedError(
            "Method `process logs batch` should have a concrete implementation for the adapter"
        )


class _LogsBatch(object):
    """
    A group of log entries that are to be processed together by the adapter. All the appended log
    entries to the batch will be processed by the adapter in one go
    """

    def __init__(self):
        self._last_log_date = None
        self._logs = []
        self._current_index = -1

    @property
    def last_log_date(self):
        """
        Returns the last log entry date

        :return: The date of the last log entry that was appended to the batch

        :rtype: datetime.datetime
        """
        return self._last_log_date

    def append(self, date, message):
        """
        Append a log entry to the batch

        :param date: The date in UTC of the log message
        :param message: The log message

        :type date: datetime.datetime
        :type message: str
        """
        if date is None:
            raise ValueError("Date must be specified and cannot be None")

        if message is None:
            raise ValueError("Message must be specified and cannot be None")

        # confirm that the given date for the log is after the last log entry
        if self._last_log_date and date < self._last_log_date:
            raise ValueError("Log entry '{}' is before the last logged message".format(message))

        # append the given log entry to the batch and keep track of the last log entry date
        self._logs.append({
            "date": date,
            "message": message
        })

        self._last_log_date = date

    def __iter__(self):
        self._current_index = -1
        return self

    def next(self):
        """
        Gets the next log message to be processed. The method will block if another thread is trying
        to access the logs batch at the same time that it is being read.

        :return: The log entry in the log batch

        :rtype: dict
        """
        if self._current_index == len(self._logs) - 1:
            raise StopIteration

        self._current_index += 1
        return self._logs[self._current_index]


def adapter_factory(config):
    """
    Constructs the adapter according to the given configuration

    :param config: The configuration that is to be used to construct the adapter

    :return: The created adapter for the given configuration

    :type config: dict
    :rtype docker_logger.adapter.Adapter
    """
    if not config:
        raise ValueError("Configuration must be specified and cannot be None")

    # determine if the specified type of adapter is known
    if "type" not in config:
        raise ValueError("Adapter configuration is invalid, adapter type is not specified")

    if config["type"] not in ADAPTERS:
        raise ValueError("Adapter configuration is invalid, adapter type is not known")

    # create the adapter with the given configurations
    adapter_details = ADAPTERS[config["type"]]
    adapter_cls = import_module(adapter_details["module"])
    return getattr(adapter_cls, adapter_details["class"])(config)
