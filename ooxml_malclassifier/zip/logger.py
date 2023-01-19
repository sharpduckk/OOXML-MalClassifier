import logging


class ValidationLogger(logging.LoggerAdapter):
    def __init__(self, name):
        super(ValidationLogger, self).__init__(logging.getLogger(name), {})
        self.data = []

    def log(self, level, msg, *args, **kwargs):
        """
        Delegate a log call to the underlying logger, after adding
        contextual information from this adapter instance.
        """
        if self.isEnabledFor(level):
            msg, kwargs = self.process(msg, kwargs)
            if level >= 40:
                self.data.append({"log": msg, "level": level})
            self.logger.log(level, msg, *args, **kwargs)