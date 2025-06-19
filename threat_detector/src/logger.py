import logging

def setup_logger(log_file="app.log"):
    logger = logging.getLogger("ioc_enrichment")
    logger.setLevel(logging.DEBUG)

    # File handler
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)

    # Console handler (optional)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)

    # Formatter
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    # Add handlers if not already added
    if not logger.handlers:
        logger.addHandler(fh)
        logger.addHandler(ch)

    return logger
