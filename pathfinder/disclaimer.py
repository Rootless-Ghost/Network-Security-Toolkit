"""
Ethical use disclaimer for PathFinder.
Users must confirm explicit authorization before any offensive analysis runs.
"""

import logging
import sys

logger = logging.getLogger(__name__)


class EthicalUseDisclaimer:
    """Display and enforce ethical usage of PathFinder."""

    @staticmethod
    def show() -> None:
        disclaimer = """
        #######################################################################
        #                                                                     #
        #                        !!! WARNING !!!                              #
        #                                                                     #
        #  PathFinder is designed for AUTHORIZED SECURITY TESTING ONLY.      #
        #  Using this tool against systems without explicit written           #
        #  permission is ILLEGAL and may result in criminal prosecution       #
        #  under the Computer Fraud and Abuse Act (CFAA), the Computer       #
        #  Misuse Act, or equivalent legislation in your jurisdiction.        #
        #                                                                     #
        #  This tool is intended for:                                         #
        #    - Authorized penetration testing engagements                     #
        #    - CTF (Capture the Flag) competitions                            #
        #    - Security research in isolated lab environments                 #
        #    - Red team operations with explicit written authorization        #
        #                                                                     #
        #  The author accepts NO LIABILITY for any misuse of this tool.       #
        #  You are solely responsible for your actions and their consequences #
        #  under applicable law.                                              #
        #                                                                     #
        #######################################################################
        """
        print(disclaimer)
        try:
            answer = input(
                "\nDo you confirm you have EXPLICIT WRITTEN AUTHORIZATION to assess "
                "the target network(s)? (yes/no): "
            ).strip().lower()
        except EOFError:
            answer = "no"

        if answer not in ("yes", "y"):
            logger.critical("Authorization not confirmed. Exiting.")
            sys.exit(1)

        logger.info("User confirmed ethical use and explicit authorization.")
        print("[*] Authorization confirmed. Proceeding with assessment.\n")
