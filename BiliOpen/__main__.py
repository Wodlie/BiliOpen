#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

import argparse
import hashlib
import json
import math
import os
import re
import requests
import shlex
import signal
import struct
import sys
import threading
import time
import traceback
import types
import zlib
import io
from PIL import Image
from BiliOpen import __version__
from BiliOpen.bilibili import Bilibili

log = Bilibili._log

bundle_dir = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))

default_url = lambda sha1: f"http://i0.hdslb.com/bfs/openplatform/{sha1}.png"
meta_string = lambda url: ("biliopen://" + re.findall(r"[a-fA-F0-9]{40}", url)[0]) if re.match(r"^http(s?)://i0.hdslb.com/bfs/openplatform/[a-fA-F0-9]{40}.png$", url) else url
size_string = lambda byte: f"{byte / 1024 / 1024 / 1024:.2f} GB" if byte > 1024 * 1024 * 1024 else f"{byte / 1024 / 1024:.2f} MB" if byte > 1024 * 1024 else f"{byte / 1024:.2f} KB" if byte > 1024 else f"{int(byte)} B"

def create_carrier_image(width=8000, height=6000):
    """创建载体图像"""
    img = Image.new('RGB', (width, height), color='black')
    return img

def hide_data_in_png(data, chunk_prefix='ziPd', background_image=None):
    """
    将数据隐藏到PNG图像中
    :param data: 要隐藏的二进制数据
    :param chunk_prefix: 自定义块前缀（必须4字符）
    :param background_image: 背景图像路径或二进制数据，如果为None则使用默认黑色背景
    :return: 包含隐藏数据的PNG二进制
    """
    # 获取载体图像的PNG数据
    if background_image is None:
        # 创建默认载体图像
        carrier_img = create_carrier_image()
        png_buffer = io.BytesIO()
        carrier_img.save(png_buffer, format='PNG')
        png_data = png_buffer.getvalue()
    elif isinstance(background_image, str):
        # 从文件路径读取PNG图像
        try:
            with open(background_image, 'rb') as f:
                png_data = f.read()
            # 验证是否为有效PNG文件
            if not png_data.startswith(b'\x89PNG\r\n\x1a\n'):
                raise ValueError(f"指定的文件不是有效的PNG格式: {background_image}")
        except Exception as e:
            raise ValueError(f"无法读取背景图像文件 {background_image}: {e}")
    elif isinstance(background_image, bytes):
        # 直接使用二进制数据
        png_data = background_image
        if not png_data.startswith(b'\x89PNG\r\n\x1a\n'):
            raise ValueError("提供的背景图像数据不是有效的PNG格式")
    else:
        raise ValueError("background_image必须是文件路径(str)、二进制数据(bytes)或None")
    
    # PNG文件签名和关键块标识
    PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'
    IHDR = b'IHDR'
    IDAT = b'IDAT'
    IEND = b'IEND'
    
    # 查找关键块位置
    pos = len(PNG_SIGNATURE)
    chunks = []
    idat_end = None
    
    # 解析现有块
    while pos < len(png_data):
        # 读取块长度和类型
        chunk_len = struct.unpack('>I', png_data[pos:pos+4])[0]
        chunk_type = png_data[pos+4:pos+8]
        chunk_end = pos + 8 + chunk_len + 4  # +4为CRC
        
        # 记录所有块
        chunks.append((chunk_type, png_data[pos:chunk_end]))
        
        # 记录最后一个IDAT块结束位置
        if chunk_type == IDAT:
            idat_end = chunk_end
        
        pos = chunk_end
    
    if idat_end is None:
        raise ValueError("无效的PNG文件：未找到IDAT块")
    
    # 分割数据到多个自定义块
    chunk_size = 65535 - 4  # 留4字节给chunk序号
    data_chunks = []
    chunk_num = 1
    
    for i in range(0, len(data), chunk_size):
        # 使用固定的chunk type name
        chunk_type_name = chunk_prefix.encode('ascii')[:4].ljust(4, b'\x00')
        
        # 获取当前数据段
        current_data = data[i:i+chunk_size]
        
        # 在数据前添加4字节的chunk序号
        chunk_data = struct.pack('>I', chunk_num) + current_data
        
        # 计算CRC（块类型+数据）
        crc = zlib.crc32(chunk_type_name + chunk_data) & 0xFFFFFFFF
        
        # 构建完整块 [长度(4) + 类型(4) + 数据(n) + CRC(4)]
        chunk = struct.pack('>I', len(chunk_data)) + chunk_type_name + chunk_data + struct.pack('>I', crc)
        data_chunks.append(chunk)
        chunk_num += 1
    
    # 构建新PNG文件
    new_png = bytearray(PNG_SIGNATURE)
    
    # 插入原始块直到最后一个IDAT之后
    for chunk_type, chunk_data in chunks:
        new_png.extend(chunk_data)
        if chunk_type == IDAT:
            # 在最后一个IDAT后插入自定义块
            for data_chunk in data_chunks:
                new_png.extend(data_chunk)
    
    return bytes(new_png)

def extract_data_from_png(png_data, chunk_prefix='ziPd'):
    """
    从PNG文件中提取隐藏的数据
    :param png_data: PNG二进制数据
    :param chunk_prefix: 自定义块前缀（必须4字符）
    :return: 提取的二进制数据
    """
    # PNG文件签名
    PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'
    if not png_data.startswith(PNG_SIGNATURE):
        raise ValueError("无效的PNG文件")
    
    # 查找关键块位置
    pos = len(PNG_SIGNATURE)
    custom_chunks = {}  # 用字典存储，键为块编号，值为数据
    custom_type = chunk_prefix.encode('ascii')[:4].ljust(4, b'\x00')
    
    # 遍历所有块
    while pos < len(png_data):
        # 读取块长度和类型
        chunk_len = struct.unpack('>I', png_data[pos:pos+4])[0]
        chunk_type = png_data[pos+4:pos+8]
        chunk_start = pos + 8
        chunk_end = chunk_start + chunk_len
        crc = png_data[chunk_end:chunk_end+4]
        
        # 检查是否自定义块
        if chunk_type == custom_type:
            # 获取块数据
            chunk_data = png_data[chunk_start:chunk_end]
            if len(chunk_data) >= 4:
                # 前4字节是chunk序号
                chunk_num = struct.unpack('>I', chunk_data[:4])[0]
                actual_data = chunk_data[4:]
                custom_chunks[chunk_num] = actual_data
        
        # 移动到下一个块
        pos = chunk_end + 4
    
    # 按编号顺序重建数据
    extracted_data = bytearray()
    for chunk_num in sorted(custom_chunks.keys()):
        extracted_data.extend(custom_chunks[chunk_num])
    
    return bytes(extracted_data)

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
    sha1 = hashlib.sha1()
    if isinstance(data, types.GeneratorType):
        for chunk in data:
            sha1.update(chunk)
    else:
        sha1.update(data)
    return sha1.hexdigest() if hexdigest else sha1.digest()

def fetch_meta(string):
    if re.match(r"^biliopen://[a-fA-F0-9]{40}$", string) or re.match(r"^[a-fA-F0-9]{40}$", string):
        full_meta = image_download(default_url(re.findall(r"[a-fA-F0-9]{40}", string)[0]))
    elif string.startswith("http://") or string.startswith("https://"):
        full_meta = image_download(string)
    else:
        return None
    try:
        # For PNG format, extract data from custom chunks
        meta_data = extract_data_from_png(full_meta, chunk_prefix='ziPd')
        meta_dict = json.loads(meta_data.decode("utf-8"))
        return meta_dict
    except:
        # Fallback to old BMP format for backward compatibility
        try:
            meta_dict = json.loads(full_meta[62:].decode("utf-8"))
            return meta_dict
        except:
            return None

def image_upload(data, cookies):
    url = "https://api.bilibili.com/x/upload/web/image"
    headers = {
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36",
    }
    
    # Extract CSRF token from bili_jct cookie
    csrf_token = cookies.get('bili_jct', '')
    if not csrf_token:
        log("错误：无法从cookie中获取bili_jct字段，请检查cookie是否完整")
        return None
    
    files = {
        'file': (f"{int(time.time() * 1000)}.png", data, 'image/png'),
    }
    
    form_data = {
        'bucket': 'openplatform',
        'csrf': csrf_token,
    }
    
    try:
        response = requests.post(url, headers=headers, cookies=cookies, files=files, data=form_data).json()
    except:
        response = None
    return response

def image_download(url):
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

def read_history():
    try:
        with open(os.path.join(bundle_dir, "history.json"), "r", encoding="utf-8") as f:
            history = json.loads(f.read())
    except:
        history = {}
    return history

def read_in_chunk(file_name, chunk_size=16 * 1024 * 1024, chunk_number=-1):
    chunk_counter = 0
    with open(file_name, "rb") as f:
        while True:
            data = f.read(chunk_size)
            if data != b"" and (chunk_number == -1 or chunk_counter < chunk_number):
                yield data
                chunk_counter += 1
            else:
                return

def load_cookies_from_file():
    """Load cookies from cookie.txt file in HEADER STRING format"""
    cookie_file = "cookie.txt"  # Use current working directory
    
    if not os.path.exists(cookie_file):
        log("未找到cookie.txt文件，请创建该文件并填入有效的cookie")
        log("cookie格式为HEADER STRING，例如：")
        log("SESSDATA=xxx; bili_jct=xxx")
        return None
    
    try:
        with open(cookie_file, "r", encoding="utf-8") as f:
            cookie_string = f.read().strip()
        
        if not cookie_string:
            log("cookie.txt文件为空，请填入有效的cookie")
            log("cookie格式为HEADER STRING，例如：")
            log("SESSDATA=xxx; bili_jct=xxx")
            return None
        
        # Parse cookie string into dictionary
        cookies = {}
        for cookie_pair in cookie_string.split(';'):
            cookie_pair = cookie_pair.strip()
            if '=' in cookie_pair:
                key, value = cookie_pair.split('=', 1)
                cookies[key.strip()] = value.strip()
        
        # Validate that essential cookies are present
        essential_cookies = ['SESSDATA', 'bili_jct']
        missing_cookies = [cookie for cookie in essential_cookies if cookie not in cookies]
        
        if missing_cookies:
            log(f"cookie中缺少必要字段: {', '.join(missing_cookies)}")
            log("请确保cookie包含SESSDATA, bili_jct等必要字段")
            return None
        
        return cookies
        
    except Exception as e:
        log(f"读取cookie.txt文件失败: {e}")
        log("请检查文件格式是否正确，cookie格式为HEADER STRING")
        return None



def upload_handle(args):
    def core(index, block):
        try:
            block_sha1 = calc_sha1(block, hexdigest=True)
            full_block = hide_data_in_png(block, chunk_prefix='ziPd', background_image=args.picture)
            full_block_sha1 = calc_sha1(full_block, hexdigest=True)
            url = is_skippable(full_block_sha1)
            if url:
                log(f"分块{index + 1}/{block_num}上传完毕")
                block_dict[index] = {
                    'url': url,
                    'size': len(block),
                    'sha1': block_sha1,
                }
            else:
                # log(f"分块{index + 1}/{block_num}开始上传")
                for _ in range(10):
                    if terminate_flag.is_set():
                        return
                    response = image_upload(full_block, cookies)
                    if response:
                        if response['code'] == 0:
                            url = response['data']['location']
                            log(f"分块{index + 1}/{block_num}上传完毕")
                            block_dict[index] = {
                                'url': url,
                                'size': len(block),
                                'sha1': block_sha1,
                            }
                            return
                        elif response['code'] == -4:
                            terminate_flag.set()
                            log(f"分块{index + 1}/{block_num}第{_ + 1}次上传失败, 请重新登录")
                            return
                    log(f"分块{index + 1}/{block_num}第{_ + 1}次上传失败")
                else:
                    terminate_flag.set()
        except:
            terminate_flag.set()
            traceback.print_exc()
        finally:
            done_flag.release()

    def is_skippable(sha1):
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

    def write_history(first_4mb_sha1, meta_dict, url):
        history = read_history()
        history[first_4mb_sha1] = meta_dict
        history[first_4mb_sha1]['url'] = url
        with open(os.path.join(bundle_dir, "history.json"), "w", encoding="utf-8") as f:
            f.write(json.dumps(history, ensure_ascii=False, indent=2))

    start_time = time.time()
    file_name = args.file
    if not os.path.exists(file_name):
        log(f"文件{file_name}不存在")
        return None
    if os.path.isdir(file_name):
        log("暂不支持上传文件夹")
        return None
    log(f"上传: {os.path.basename(file_name)} ({size_string(os.path.getsize(file_name))})")
    first_4mb_sha1 = calc_sha1(read_in_chunk(file_name, chunk_size=4 * 1024 * 1024, chunk_number=1), hexdigest=True)
    history = read_history()
    if first_4mb_sha1 in history:
        url = history[first_4mb_sha1]['url']
        log(f"文件已于{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(history[first_4mb_sha1]['time']))}上传, 共有{len(history[first_4mb_sha1]['block'])}个分块")
        log(f"META URL -> {meta_string(url)}")
        return url
    cookies = load_cookies_from_file()
    if cookies is None:
        return None
    log(f"线程数: {args.thread}")
    done_flag = threading.Semaphore(0)
    terminate_flag = threading.Event()
    thread_pool = []
    block_dict = {}
    block_num = math.ceil(os.path.getsize(file_name) / (args.block_size * 1024 * 1024))
    for index, block in enumerate(read_in_chunk(file_name, chunk_size=args.block_size * 1024 * 1024)):
        if len(thread_pool) >= args.thread:
            done_flag.acquire()
        if not terminate_flag.is_set():
            thread_pool.append(threading.Thread(target=core, args=(index, block)))
            thread_pool[-1].start()
        else:
            log("已终止上传, 等待线程回收")
            break
    for thread in thread_pool:
        thread.join()
    if terminate_flag.is_set():
        return None
    sha1 = calc_sha1(read_in_chunk(file_name), hexdigest=True)
    meta_dict = {
        'time': int(time.time()),
        'filename': os.path.basename(file_name),
        'size': os.path.getsize(file_name),
        'sha1': sha1,
        'block': [block_dict[i] for i in range(len(block_dict))],
    }
    meta = json.dumps(meta_dict, ensure_ascii=False).encode("utf-8")
    full_meta = hide_data_in_png(meta, chunk_prefix='ziPd', background_image=args.picture)
    for _ in range(10):
        response = image_upload(full_meta, cookies)
        if response and response['code'] == 0:
            url = response['data']['location']
            log("元数据上传完毕")
            log(f"{meta_dict['filename']} ({size_string(meta_dict['size'])}) 上传完毕, 用时{time.time() - start_time:.1f}秒, 平均速度{size_string(meta_dict['size'] / (time.time() - start_time))}/s")
            log(f"META URL -> {meta_string(url)}")
            write_history(first_4mb_sha1, meta_dict, url)
            return url
        log(f"元数据第{_ + 1}次上传失败")
    else:
        return None

def download_handle(args):
    def core(index, block_dict):
        try:
            # log(f"分块{index + 1}/{len(meta_dict['block'])}开始下载")
            for _ in range(10):
                if terminate_flag.is_set():
                    return
                block = image_download(block_dict['url'])
                if block:
                    # Try PNG format first
                    try:
                        block_data = extract_data_from_png(block, chunk_prefix='ziPd')
                    except:
                        # Fallback to old BMP format for backward compatibility
                        block_data = block[62:]
                    
                    if calc_sha1(block_data, hexdigest=True) == block_dict['sha1']:
                        file_lock.acquire()
                        f.seek(block_offset(index))
                        f.write(block_data)
                        file_lock.release()
                        log(f"分块{index + 1}/{len(meta_dict['block'])}下载完毕")
                        return
                    else:
                        log(f"分块{index + 1}/{len(meta_dict['block'])}校验未通过")
                else:
                    log(f"分块{index + 1}/{len(meta_dict['block'])}第{_ + 1}次下载失败")
            else:
                terminate_flag.set()
        except:
            terminate_flag.set()
            traceback.print_exc()
        finally:
            done_flag.release()

    def block_offset(index):
        return sum(meta_dict['block'][i]['size'] for i in range(index))

    def is_overwritable(file_name):
        if args.force:
            return True
        else:
            return (input("文件已存在, 是否覆盖? [y/N] ") in ["y", "Y"])

    start_time = time.time()
    meta_dict = fetch_meta(args.meta)
    if meta_dict:
        file_name = args.file if args.file else meta_dict['filename']
        log(f"下载: {os.path.basename(file_name)} ({size_string(meta_dict['size'])}), 共有{len(meta_dict['block'])}个分块, 上传于{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(meta_dict['time']))}")
    else:
        log("元数据解析失败")
        return None
    log(f"线程数: {args.thread}")
    download_block_list = []
    if os.path.exists(file_name):
        if os.path.getsize(file_name) == meta_dict['size'] and calc_sha1(read_in_chunk(file_name), hexdigest=True) == meta_dict['sha1']:
            log("文件已存在, 且与服务器端内容一致")
            return file_name
        elif is_overwritable(file_name):
            with open(file_name, "rb") as f:
                for index, block_dict in enumerate(meta_dict['block']):
                    f.seek(block_offset(index))
                    if calc_sha1(f.read(block_dict['size']), hexdigest=True) == block_dict['sha1']:
                        # log(f"分块{index + 1}/{len(meta_dict['block'])}校验通过")
                        pass
                    else:
                        # log(f"分块{index + 1}/{len(meta_dict['block'])}校验未通过")
                        download_block_list.append(index)
            log(f"{len(download_block_list)}/{len(meta_dict['block'])}个分块待下载")
        else:
            return None
    else:
        download_block_list = list(range(len(meta_dict['block'])))
    done_flag = threading.Semaphore(0)
    terminate_flag = threading.Event()
    file_lock = threading.Lock()
    thread_pool = []
    with open(file_name, "r+b" if os.path.exists(file_name) else "wb") as f:
        for index in download_block_list:
            if len(thread_pool) >= args.thread:
                done_flag.acquire()
            if not terminate_flag.is_set():
                thread_pool.append(threading.Thread(target=core, args=(index, meta_dict['block'][index])))
                thread_pool[-1].start()
            else:
                log("已终止下载, 等待线程回收")
                break
        for thread in thread_pool:
            thread.join()
        if terminate_flag.is_set():
            return None
        f.truncate(sum(block['size'] for block in meta_dict['block']))
    log(f"{os.path.basename(file_name)} ({size_string(meta_dict['size'])}) 下载完毕, 用时{time.time() - start_time:.1f}秒, 平均速度{size_string(meta_dict['size'] / (time.time() - start_time))}/s")
    sha1 = calc_sha1(read_in_chunk(file_name), hexdigest=True)
    if sha1 == meta_dict['sha1']:
        log("文件校验通过")
        return file_name
    else:
        log("文件校验未通过")
        return None

def info_handle(args):
    meta_dict = fetch_meta(args.meta)
    if meta_dict:
        print(f"文件名: {meta_dict['filename']}")
        print(f"大小: {size_string(meta_dict['size'])}")
        print(f"SHA-1: {meta_dict['sha1']}")
        print(f"上传时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(meta_dict['time']))}")
        print(f"分块数: {len(meta_dict['block'])}")
        for index, block_dict in enumerate(meta_dict['block']):
            print(f"分块{index + 1} ({size_string(block_dict['size'])}) URL: {block_dict['url']}")
    else:
        print("元数据解析失败")

def history_handle(args):
    history = read_history()
    if history:
        for index, meta_dict in enumerate(history.values()):
            prefix = f"[{index + 1}]"
            print(f"{prefix} {meta_dict['filename']} ({size_string(meta_dict['size'])}), 共有{len(meta_dict['block'])}个分块, 上传于{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(meta_dict['time']))}")
            print(f"{' ' * len(prefix)} META URL -> {meta_string(meta_dict['url'])}")
    else:
        print(f"暂无历史记录")

def main():
    signal.signal(signal.SIGINT, lambda signum, frame: os.kill(os.getpid(), 9))
    parser = argparse.ArgumentParser(prog="BiliOpen", description="Make Bilibili A Great Cloud Storage!", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-v", "--version", action="version", version=f"BiliOpen version: {__version__}")
    subparsers = parser.add_subparsers()
    upload_parser = subparsers.add_parser("upload", help="upload a file")
    upload_parser.add_argument("file", help="name of the file to upload")
    upload_parser.add_argument("-b", "--block-size", default=4, type=int, help="block size in MB")
    upload_parser.add_argument("-t", "--thread", default=4, type=int, help="upload thread number")
    upload_parser.add_argument("-p", "--picture", help="path to custom PNG background image (optional)")
    upload_parser.set_defaults(func=upload_handle)
    download_parser = subparsers.add_parser("download", help="download a file")
    download_parser.add_argument("meta", help="meta url")
    download_parser.add_argument("file", nargs="?", default="", help="new file name")
    download_parser.add_argument("-f", "--force", action="store_true", help="force to overwrite if file exists")
    download_parser.add_argument("-t", "--thread", default=8, type=int, help="download thread number")
    download_parser.set_defaults(func=download_handle)
    info_parser = subparsers.add_parser("info", help="show meta info")
    info_parser.add_argument("meta", help="meta url")
    info_parser.set_defaults(func=info_handle)
    history_parser = subparsers.add_parser("history", help="show upload history")
    history_parser.set_defaults(func=history_handle)
    shell = False
    while True:
        if shell:
            args = shlex.split(input("BiliOpen > "))
            try:
                args = parser.parse_args(args)
                args.func(args)
            except:
                pass
        else:
            args = parser.parse_args()
            try:
                args.func(args)
                break
            except AttributeError:
                shell = True
                subparsers.add_parser("help", help="show this help message").set_defaults(func=lambda _: parser.parse_args(["--help"]).func())
                subparsers.add_parser("version", help="show program's version number").set_defaults(func=lambda _: parser.parse_args(["--version"]).func())
                subparsers.add_parser("exit", help="exit program").set_defaults(func=lambda _: os._exit(0))
                parser.print_help()

if __name__ == "__main__":
    main()
