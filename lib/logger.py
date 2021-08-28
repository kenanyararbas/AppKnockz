import colorsys
import sys
from pyfiglet import Figlet
import logging
import coloredlogs


class logger:
    logger = logging.getLogger(__name__)  # get a specific logger object
    coloredlogs.install(level='verbose')  # install a handler on the root logger with level debug
    coloredlogs.install(level='verbose', logger=logger)  # pass a specific logger object
    coloredlogs.install(
        level='verbose', logger=logger,
        fmt='%(asctime)s.%(msecs)03d %(filename)s:%(lineno)d %(levelname)s %(message)s'
    )

notifications = []


def add_notification(notification, type):
    notifications.append(notification)
    if type == "warning":
        logging.warning(notification + "\n")
    elif type == "critical":
        logging.critical(notification + "\n")
    elif type == "error":
        logging.error(notification + "\n")
    else:
        logging.info(notification + "\n")


def print_banner():
    custom_fig = Figlet(font='graffiti')
    print(custom_fig.renderText("AppKnockz"))




if __name__ == '__main__':
    add_notification(notification="Test", type="critical")
