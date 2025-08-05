#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

import setuptools
import os
import re

# Read version from __init__.py without importing the module
def get_version():
    init_file = os.path.join(os.path.dirname(__file__), "BiliOpen", "__init__.py")
    with open(init_file, "r", encoding="utf-8") as f:
        content = f.read()
    version_match = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]', content, re.MULTILINE)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")

# Read author and email from __init__.py without importing the module
def get_author_info():
    init_file = os.path.join(os.path.dirname(__file__), "BiliOpen", "__init__.py")
    with open(init_file, "r", encoding="utf-8") as f:
        content = f.read()
    
    author_match = re.search(r'^__author__\s*=\s*[\'"]([^\'"]*)[\'"]', content, re.MULTILINE)
    email_match = re.search(r'^__email__\s*=\s*[\'"]([^\'"]*)[\'"]', content, re.MULTILINE)
    
    author = author_match.group(1) if author_match else "Unknown"
    email = email_match.group(1) if email_match else "unknown@example.com"
    
    return author, email

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    install_requires = fh.read().splitlines()

author, email = get_author_info()

setuptools.setup(
    name="BiliOpen",
    version=get_version(),
    url="https://github.com/Wodlie/BiliOpen",
    author=author,
    author_email=email,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: Chinese (Simplified)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.7",
        "Topic :: Communications :: File Sharing",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Utilities",
    ],
    description="☁️ 哔哩开放云，支持任意文件的全速上传与下载",
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords=[
        "bilibili",
        "cloud",
        "disk",
        "drive",
        "storage",
        "pan",
        "yun",
        "B站",
        "哔哩哔哩",
        "网盘"
    ],
    install_requires=install_requires,
    python_requires=">=3.6",
    entry_points={
        'console_scripts': [
            "BiliOpen=BiliOpen.__main__:main",
        ],
    },
    packages=setuptools.find_packages(),
)
