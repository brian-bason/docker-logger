"""
The adapters that can be used to send captured log messages to a central location
"""
import abc

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

        self._config = config

    @abc.abstractmethod
    def process_logs(self, logs=list()):
        """
        Processes the given list of logs according to the specific adapter. The logs can either be
        saved to a remote location or displayed on a console.

        :param logs: The list of logs that are to be processed by the adapter

        :type logs: list[dict]
        """
        raise NotImplementedError("Process logs method must be implemented by concrete class")

    @property
    def max_batched_logs(self):
        """
        Gets the maximum number of logs that can be batched and sent in one go

        :return: The max number of logs that should be batched for the adapter

        :rtype: int
        """
        return 1


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
