#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
BiliOpen API Core Module
提供简洁的程序化接口用于上传和下载文件
"""

import hashlib
import json
import math
import os
import re
import requests
import struct
import threading
import time
import traceback
import types
import zlib
import io
from typing import Optional, Dict, Any, Union, BinaryIO
from BiliOpen.bilibili import Bilibili

log = Bilibili._log

# 工具函数
default_url = lambda sha1: f"http://i0.hdslb.com/bfs/album/{sha1}.x-ms-bmp"
meta_string = lambda url: ("biliopen://" + re.findall(r"[a-fA-F0-9]{40}", url)[0]) if re.match(r"^http(s?)://i0.hdslb.com/bfs/album/[a-fA-F0-9]{40}.x-ms-bmp$", url) else url
size_string = lambda byte: f"{byte / 1024 / 1024 / 1024:.2f} GB" if byte > 1024 * 1024 * 1024 else f"{byte / 1024 / 1024:.2f} MB" if byte > 1024 * 1024 else f"{byte / 1024:.2f} KB" if byte > 1024 else f"{int(byte)} B"

def bmp_header(data):
    return b"BM" \
        + struct.pack("<l", 14 + 40 + 8 + len(data)) \
        + b"\x00\x00" \
        + b"\x00\x00" \
        + b"\x3e\x00\x00\x00" \
        + b"\x28\x00\x00\x00" \
        + struct.pack("<l", len(data)) \
        + b"\x01\x00\x00\x00" \
        + b"\x01\x00" \
        + b"\x01\x00" \
        + b"\x00\x00\x00\x00" \
        + struct.pack("<l", math.ceil(len(data) / 8)) \
        + b"\x00\x00\x00\x00" \
        + b"\x00\x00\x00\x00" \
        + b"\x00\x00\x00\x00" \
        + b"\x00\x00\x00\x00" \
        + b"\x00\x00\x00\x00\xff\xff\xff\x00"

def calc_sha1(data, hexdigest=False):
    """计算SHA1哈希值"""
    sha1 = hashlib.sha1()
    if isinstance(data, types.GeneratorType):
        for chunk in data:
            sha1.update(chunk)
    else:
        sha1.update(data)
    return sha1.hexdigest() if hexdigest else sha1.digest()


def read_in_chunk(file_name, chunk_size=16 * 1024 * 1024, chunk_number=-1):
    """按块读取文件"""
    chunk_counter = 0
    with open(file_name, "rb") as f:
        while True:
            data = f.read(chunk_size)
            if data != b"" and (chunk_number == -1 or chunk_counter < chunk_number):
                yield data
                chunk_counter += 1
            else:
                return


class BiliOpenAPI:
    """BiliOpen核心API类"""
    
    def __init__(self, cookies: Optional[Dict[str, str]] = None, cookie_file: Optional[str] = None):
        """
        初始化BiliOpen API
        
        Args:
            cookies: Cookie字典，格式如 {'SESSDATA': 'xxx', 'bili_jct': 'xxx'}
            cookie_file: Cookie文件路径，默认为当前目录下的cookie.txt
        """
        self.cookies: Optional[Dict[str, str]] = None
        if cookies:
            self.cookies = cookies
        elif cookie_file or os.path.exists("cookie.txt"):
            self.cookies = self._load_cookies_from_file(cookie_file or "cookie.txt")
        
        if not self.cookies:
            raise ValueError("未提供有效的cookies，请通过cookies参数或cookie.txt文件提供")
    
    def _load_cookies_from_file(self, cookie_file: str) -> Optional[Dict[str, str]]:
        """从文件加载cookies"""
        if not os.path.exists(cookie_file):
            return None
        
        try:
            with open(cookie_file, "r", encoding="utf-8") as f:
                cookie_string = f.read().strip()
            
            if not cookie_string:
                return None
            
            cookies = {}
            for cookie_pair in cookie_string.split(';'):
                cookie_pair = cookie_pair.strip()
                if '=' in cookie_pair:
                    key, value = cookie_pair.split('=', 1)
                    cookies[key.strip()] = value.strip()
            
            essential_cookies = ['SESSDATA', 'bili_jct']
            missing_cookies = [cookie for cookie in essential_cookies if cookie not in cookies]
            
            if missing_cookies:
                return None
            
            return cookies
        except Exception:
            return None
    
    def _image_upload(self, data: bytes) -> Optional[Dict[str, Any]]:
        """上传图片到B站"""
        url = "https://api.vc.bilibili.com/api/v1/drawImage/upload"
        headers = {
            'Origin': "https://t.bilibili.com",
            'Referer': "https://t.bilibili.com/",
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36",
        }
        files = {
            'file_up': (f"{int(time.time() * 1000)}.bmp", data),
            'biz': "draw",
            'category': "daily",
        }
        try:
            response = requests.post(url, headers=headers, cookies=self.cookies, files=files, timeout=300).json()
        except:
            response = None
        return response
        
    def _image_download(self, url: str) -> Optional[bytes]:
        """从URL下载图片"""
        headers = {
            'Referer': "http://t.bilibili.com/",
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36",
        }
        content = []
        last_chunk_time = None
        try:
            for chunk in requests.get(url, headers=headers, timeout=10, stream=True).iter_content(128 * 1024):
                if last_chunk_time is not None and time.time() - last_chunk_time > 5:
                    return None
                content.append(chunk)
                last_chunk_time = time.time()
            return b"".join(content)
        except:
            return None
    
    def _is_skippable(self, sha1: str) -> Optional[str]:
        """检查文件是否已存在"""
        url = default_url(sha1)
        headers = {
            'Referer': "http://t.bilibili.com/",
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36",
        }
        for _ in range(5):
            try:
                response = requests.head(url, headers=headers, timeout=10)
                return url if response.status_code == 200 else None
            except:
                pass
        return None
    
    def fetch_meta(self, meta_string: str) -> Optional[Dict[str, Any]]:
        """
        获取元数据
        
        Args:
            meta_string: 元数据字符串，可以是biliopen://xxx, http://xxx 或者40位SHA1
            
        Returns:
            元数据字典，失败返回None
        """
        if re.match(r"^biliopen://[a-fA-F0-9]{40}$", meta_string) or re.match(r"^[a-fA-F0-9]{40}$", meta_string):
            full_meta = self._image_download(default_url(re.findall(r"[a-fA-F0-9]{40}", meta_string)[0]))
        elif meta_string.startswith("http://") or meta_string.startswith("https://"):
            full_meta = self._image_download(meta_string)
        else:
            return None
        
        if not full_meta:
            return None
        
        try:
            meta_data = bmp_header(full_meta) + full_meta
            meta_dict = json.loads(meta_data.decode("utf-8"))
            return meta_dict
        except:
            try:
                meta_dict = json.loads(full_meta[62:].decode("utf-8"))
                return meta_dict
            except:
                return None
    
    def upload_bytes(self, data: bytes, filename: Optional[str] = None, block_size_mb: int = 4, thread_count: int = 4, background_image=None) -> Optional[str]:
        """
        上传二进制数据
        
        Args:
            data: 要上传的二进制数据
            filename: 文件名（可选）
            block_size_mb: 分块大小（MB）
            thread_count: 线程数
            background_image: 自定义背景图像（文件路径或二进制数据），可选
            
        Returns:
            上传成功返回meta URL，失败返回None
        """
        if not filename:
            filename = f"upload_{int(time.time())}.bin"
        
        start_time = time.time()
        data_size = len(data)
        
        # 计算分块
        block_size = block_size_mb * 1024 * 1024
        block_num = math.ceil(data_size / block_size)
        
        # 多线程上传分块
        done_flag = threading.Semaphore(0)
        terminate_flag = threading.Event()
        thread_pool = []
        block_dict = {}
        
        def upload_block(index: int, block_data: bytes):
            try:
                block_sha1 = calc_sha1(block_data, hexdigest=True)
                full_block = bmp_header(block_data) + block_data
                full_block_sha1 = calc_sha1(full_block, hexdigest=True)
                
                # 检查是否已存在
                url = self._is_skippable(str(full_block_sha1))
                if url:
                    block_dict[index] = {
                        'url': url,
                        'size': len(block_data),
                        'sha1': block_sha1,
                    }
                    return
                
                # 上传新分块
                for attempt in range(10):
                    if terminate_flag.is_set():
                        return
                    
                    response = self._image_upload(full_block)
                    if response and response['code'] == 0:
                        url = response['data']['location']
                        block_dict[index] = {
                            'url': url,
                            'size': len(block_data),
                            'sha1': block_sha1,
                        }
                        return
                    elif response and response['code'] == -4:
                        terminate_flag.set()
                        raise ValueError("请重新登录")
                
                terminate_flag.set()
                raise ValueError(f"分块{index + 1}上传失败")
            except Exception as e:
                terminate_flag.set()
                raise e
            finally:
                done_flag.release()
        
        # 启动上传线程
        for i in range(0, data_size, block_size):
            block_data = data[i:i + block_size]
            index = i // block_size
            
            if len(thread_pool) >= thread_count:
                done_flag.acquire()
            
            if terminate_flag.is_set():
                break
            
            thread = threading.Thread(target=upload_block, args=(index, block_data))
            thread_pool.append(thread)
            thread.start()
        
        # 等待所有线程完成
        for thread in thread_pool:
            thread.join()
        
        if terminate_flag.is_set():
            return None
        
        # 创建元数据
        sha1 = calc_sha1(data, hexdigest=True)
        meta_dict = {
            'time': int(time.time()),
            'filename': filename,
            'size': data_size,
            'sha1': sha1,
            'block': [block_dict[i] for i in range(len(block_dict))],
        }
        
        # 上传元数据
        meta = json.dumps(meta_dict, ensure_ascii=False).encode("utf-8")
        full_meta = bmp_header(meta) + meta
        
        for attempt in range(10):
            response = self._image_upload(full_meta)
            if response and response['code'] == 0:
                url = response['data']['location']
                return meta_string(url)
        
        return None
    
    def upload_file(self, file_path: str, block_size_mb: int = 4, thread_count: int = 4, background_image=None) -> Optional[str]:
        """
        上传文件
        
        Args:
            file_path: 文件路径
            block_size_mb: 分块大小（MB）
            thread_count: 线程数
            background_image: 自定义背景图像（文件路径或二进制数据），可选
            
        Returns:
            上传成功返回meta URL，失败返回None
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
        
        if os.path.isdir(file_path):
            raise ValueError("不支持上传文件夹")
        
        with open(file_path, "rb") as f:
            data = f.read()
        
        filename = os.path.basename(file_path)
        return self.upload_bytes(data, filename, block_size_mb, thread_count, background_image)
    
    def download_bytes(self, meta_string: str, thread_count: int = 8) -> Optional[bytes]:
        """
        下载文件到内存
        
        Args:
            meta_string: 元数据字符串
            thread_count: 线程数
            
        Returns:
            下载成功返回二进制数据，失败返回None
        """
        meta_dict = self.fetch_meta(meta_string)
        if not meta_dict:
            return None
        
        data_size = meta_dict['size']
        data = bytearray(data_size)
        
        done_flag = threading.Semaphore(0)
        terminate_flag = threading.Event()
        data_lock = threading.Lock()
        thread_pool = []
        
        def block_offset(index):
            return sum(meta_dict['block'][i]['size'] for i in range(index))
        
        def download_block(index: int, block_dict: Dict[str, Any]):
            try:
                for attempt in range(10):
                    if terminate_flag.is_set():
                        return
                    
                    block = self._image_download(block_dict['url'])
                    if block:
                        block_data = block[62:]
                        
                        if calc_sha1(block_data, hexdigest=True) == block_dict['sha1']:
                            data_lock.acquire()
                            offset = block_offset(index)
                            data[offset:offset + len(block_data)] = block_data
                            data_lock.release()
                            return
                
                terminate_flag.set()
                raise ValueError(f"分块{index + 1}下载失败")
            except Exception as e:
                terminate_flag.set()
                raise e
            finally:
                done_flag.release()
        
        # 启动下载线程
        for index, block_dict in enumerate(meta_dict['block']):
            if len(thread_pool) >= thread_count:
                done_flag.acquire()
            
            if terminate_flag.is_set():
                break
            
            thread = threading.Thread(target=download_block, args=(index, block_dict))
            thread_pool.append(thread)
            thread.start()
        
        # 等待所有线程完成
        for thread in thread_pool:
            thread.join()
        
        if terminate_flag.is_set():
            return None
        
        # 验证文件完整性
        result_data = bytes(data)
        if calc_sha1(result_data, hexdigest=True) == meta_dict['sha1']:
            return result_data
        else:
            return None
    
    def download_file(self, meta_string: str, output_path: Optional[str] = None, force_overwrite: bool = False, thread_count: int = 8) -> Optional[str]:
        """
        下载文件到磁盘
        
        Args:
            meta_string: 元数据字符串
            output_path: 输出文件路径，为None时使用原文件名
            force_overwrite: 是否强制覆盖已存在的文件
            thread_count: 线程数
            
        Returns:
            下载成功返回文件路径，失败返回None
        """
        meta_dict = self.fetch_meta(meta_string)
        if not meta_dict:
            return None
        
        if not output_path:
            output_path = meta_dict['filename']
        
        # 检查文件是否已存在
        if os.path.exists(output_path) and not force_overwrite:
            # 检查是否与目标文件一致
            if os.path.getsize(output_path) == meta_dict['size']:
                with open(output_path, "rb") as f:
                    if calc_sha1(f.read(), hexdigest=True) == meta_dict['sha1']:
                        return output_path
        
        data = self.download_bytes(meta_string, thread_count)
        if data and output_path:
            with open(output_path, "wb") as f:
                f.write(data)
            return output_path
        
        return None
    
    def get_file_info(self, meta_string: str) -> Optional[Dict[str, Any]]:
        """
        获取文件信息
        
        Args:
            meta_string: 元数据字符串
            
        Returns:
            文件信息字典，失败返回None
        """
        return self.fetch_meta(meta_string)


# 便捷函数
def upload(data_or_path: Union[bytes, str], cookies: Optional[Dict[str, str]] = None, 
           filename: Optional[str] = None, background_image=None, **kwargs) -> Optional[str]:
    """
    便捷上传函数
    
    Args:
        data_or_path: 二进制数据或文件路径
        cookies: Cookie字典
        filename: 文件名（当data_or_path为bytes时使用）
        background_image: 自定义背景图像（文件路径或二进制数据），可选
        **kwargs: 其他参数传递给upload方法
        
    Returns:
        上传成功返回meta URL，失败返回None
    """
    api = BiliOpenAPI(cookies=cookies)
    
    if isinstance(data_or_path, bytes):
        return api.upload_bytes(data_or_path, filename, background_image=background_image, **kwargs)
    elif isinstance(data_or_path, str):
        return api.upload_file(data_or_path, background_image=background_image, **kwargs)
    else:
        raise ValueError("data_or_path必须是bytes或文件路径字符串")


def download(meta_string: str, output_path: Optional[str] = None, cookies: Optional[Dict[str, str]] = None, 
             **kwargs) -> Union[bytes, str, None]:
    """
    便捷下载函数
    
    Args:
        meta_string: 元数据字符串
        output_path: 输出路径，为None时返回bytes
        cookies: Cookie字典
        **kwargs: 其他参数传递给download方法
        
    Returns:
        output_path为None时返回bytes，否则返回文件路径。失败返回None
    """
    api = BiliOpenAPI(cookies=cookies)
    
    if output_path is None:
        return api.download_bytes(meta_string, **kwargs)
    else:
        return api.download_file(meta_string, output_path, **kwargs)


def get_info(meta_string: str, cookies: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
    """
    便捷信息获取函数
    
    Args:
        meta_string: 元数据字符串
        cookies: Cookie字典
        
    Returns:
        文件信息字典，失败返回None
    """
    api = BiliOpenAPI(cookies=cookies)
    return api.get_file_info(meta_string)
