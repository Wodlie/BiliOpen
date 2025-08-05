#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""BiliOpen 哔哩哔哩云
https://github.com/Wodlie/BiliOpen"""

__author__ = "Hsury & Wodlie"
__email__ = "i@hsury.com"
__license__ = "SATA"
__version__ = "2.0.1"

# 导入API类和便捷函数
from .api import BiliOpenAPI, upload, download, get_info

__all__ = ['BiliOpenAPI', 'upload', 'download', 'get_info']
