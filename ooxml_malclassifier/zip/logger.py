import logging


class ValidationLogger(logging.LoggerAdapter):
    def __init__(self, name):
        super(ValidationLogger, self).__init__(logging.getLogger(name), {})
        self.data = []
        self.data_summary = {
            "Unknown compression method": 0,
            "Hidden data in extra field": 0,
            "Wrong CRC32": 0,
            "Wrong uncompressed size": 0,
            "Failed Data validation": 0,
            "Inserted data": 0,
            "Wrong number of LocalFileHeader and CentralDirectory": 0,
            "Append data": 0,
            "Failed cross validation": 0,
            "Structure anomaly": 0,
            "Data slack": 0
        }

    def log(self, level, msg, *args, extra=None, **kwargs):
        """
        Delegate a log call to the underlying logger, after adding
        contextual information from this adapter instance.
        """
        if self.isEnabledFor(level):
            if level >= 40 and extra:
                self.data.append({"log": msg, "level": level})
                log_type = extra['type']
                self.data_summary[log_type] += 1
            msg, kwargs = self.process(msg, kwargs)
            self.logger.log(level, msg, *args, **kwargs)