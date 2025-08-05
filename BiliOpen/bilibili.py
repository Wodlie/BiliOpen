#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

import time

class Bilibili:
    def __init__(self):
        pass

    @staticmethod
    def _log(message):
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))}] {message}")