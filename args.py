#!/usr/bin/env python3

import argparse


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--access-key",
        help="Access key for the API. "
             "If provided, secret key is also required."
    )

    parser.add_argument(
        "--secret-key",
        help="Secret key for the API."
    )

    parser.add_argument(
        "--session-token",
        help="Token for the API session."
    )

    parser.add_argument(
        "--profile",
        default="default",
        help="AWS profile to use in requests."
    )

    parser.add_argument(
        "--region",
        help="AWS region to inspect."
    )

    args = parser.parse_args()
    return args
