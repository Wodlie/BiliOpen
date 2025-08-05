>由于b站停用了相簿以及相关api，BiliOpen已失效，本存储库仅作为学习参考。

<h1 align="center">- BiliOpen -</h1>

<h4 align="center">☁️ 哔哩开放云，支持任意文件的全速上传与下载 ☁️</h4>

## 特色

- 轻量：无复杂依赖，资源占用少
- 自由：无文件格式与大小限制，无容量限制
- 开放：基于BiliDrive二次开源（并在此感谢原作者！）
- 安全：上传的文件需要通过生成的META URL才能访问，他人无法随意查看
- 稳定：带有分块校验与超时重试机制，在较差的网络环境中依然能确保文件的完整性
- 快速：支持多线程传输与断点续传，同时借助B站的CDN资源，能最大化地利用网络环境进行上传与下载
- API支持：提供简洁的Python API，可轻松集成到其他项目中
- 自定义背景：支持使用自定义图像作为载体，让上传的文件看起来像正常图片，增强隐蔽性

## 安装

### 方法1：下载可执行文件
前往[发布页](https://github.com/Wodlie/BiliOpen/releases/latest)获取可直接运行的二进制文件

### 方法2：使用Python运行
下载[源代码](https://github.com/Wodlie/BiliOpen/archive/master.zip)后使用Python 3.6或更高版本运行

```bash
# 安装依赖
pip install -r requirements.txt

# 创建cookie.txt文件（见下文获取方法）
# 然后就可以使用了
```

## Cookie获取方法

1. 访问 https://www.bilibili.com 并登录
2. 按F12打开开发者工具
3. 在Application/存储 > Cookies > https://www.bilibili.com 中找到：
   - `SESSDATA`
   - `bili_jct`
4. 将这些值按以下格式写入 `cookie.txt`：
   ```
   SESSDATA=你的SESSDATA值; bili_jct=你的bili_jct值
   ```

## 使用方法

### 🚀 Python API 使用（推荐）

#### 基本使用

```python
import BiliOpen

# 上传文件
meta_url = BiliOpen.upload("my_file.txt")
print(f"上传成功: {meta_url}")

# 下载文件
downloaded_file = BiliOpen.download(meta_url, "downloaded_file.txt")
print(f"下载成功: {downloaded_file}")

# 上传二进制数据
data = b"Hello, BiliOpen!"
meta_url = BiliOpen.upload(data, filename="hello.txt")

# 下载到内存
downloaded_data = BiliOpen.download(meta_url)
print(f"下载数据: {downloaded_data}")

# 获取文件信息
info = BiliOpen.get_info(meta_url)
print(f"文件信息: {info}")
```

#### 高级用法

```python
# 使用API类进行更多控制
api = BiliOpen.BiliOpenAPI()

# 自定义上传参数
meta_url = api.upload_bytes(
    data=b"Large file data",
    filename="large_file.dat",
    block_size_mb=8,    # 8MB分块
    thread_count=8      # 8个上传线程
)

# 🆕 使用自定义背景图像上传
meta_url = api.upload_file(
    "my_file.txt",
    background_image="custom_background.bmp"  # 指定背景图像
)

# 也可以传入二进制数据作为背景
with open("background.bmp", "rb") as f:
    bg_data = f.read()
meta_url = api.upload_bytes(
    data=b"File data",
    filename="file.dat",
    background_image=bg_data  # 使用二进制数据作为背景
)

# 自定义下载参数
data = api.download_bytes(
    meta_url,
    thread_count=16     # 16个下载线程
)

# 下载到文件并强制覆盖
file_path = api.download_file(
    meta_url,
    "output.dat",
    force_overwrite=True
)
```

#### 使用自定义Cookies

```python
# 方法1：传入Cookie字典
cookies = {
    'SESSDATA': 'your_sessdata',
    'bili_jct': 'your_bili_jct'
}

meta_url = BiliOpen.upload(data, cookies=cookies, filename="test.txt")

# 🆕 使用自定义背景图像上传
meta_url = BiliOpen.upload(
    "my_file.txt", 
    cookies=cookies, 
    background_image="beautiful_image.bmp"  # 指定背景图像
)

# 方法2：使用API类
api = BiliOpen.BiliOpenAPI(cookies=cookies)
meta_url = api.upload_bytes(data, "test.txt")
```

#### 错误处理

```python
try:
    meta_url = BiliOpen.upload("file.txt")
    if meta_url:
        print(f"上传成功: {meta_url}")
        
        data = BiliOpen.download(meta_url)
        if data:
            print("下载成功")
        else:
            print("下载失败")
    else:
        print("上传失败")
        
except ValueError as e:
    print(f"参数错误: {e}")
except FileNotFoundError as e:
    print(f"文件不存在: {e}")
except Exception as e:
    print(f"未知错误: {e}")
```

#### API参考

##### 便捷函数
- `BiliOpen.upload(data_or_path, cookies=None, filename=None, background_image=None, **kwargs)` - 上传文件或数据
- `BiliOpen.download(meta_string, output_path=None, cookies=None, **kwargs)` - 下载文件
- `BiliOpen.get_info(meta_string, cookies=None)` - 获取文件信息

##### BiliOpenAPI类方法
- `upload_file(file_path, block_size_mb=4, thread_count=4, background_image=None)` - 上传文件
- `upload_bytes(data, filename=None, block_size_mb=4, thread_count=4, background_image=None)` - 上传二进制数据
- `download_file(meta_string, output_path=None, force_overwrite=False, thread_count=8)` - 下载到文件
- `download_bytes(meta_string, thread_count=8)` - 下载到内存
- `get_file_info(meta_string)` - 获取文件信息

### 📟 命令行使用

#### 上传

```bash
python -m BiliOpen upload [-h] [-b BLOCK_SIZE] [-t THREAD] [-p PICTURE] file

# 参数说明:
# file: 待上传的文件路径
# -b BLOCK_SIZE: 分块大小(MB), 默认值为4
# -t THREAD: 上传线程数, 默认值为4
# -p PICTURE: 自定义背景图像路径, 默认值为纯黑背景图
```

上传完毕后，终端会打印一串META URL（通常以`biliopen://`开头）用于下载或分享，请妥善保管

#### 下载

```bash
python -m BiliOpen download [-h] [-f] [-t THREAD] meta [file]

# 参数说明:
# meta: META URL(通常以biliopen://开头)
# file: 另存为新的文件名, 不指定则保存为上传时的文件名
# -f: 覆盖已有文件
# -t THREAD: 下载线程数, 默认值为8
```

下载完毕后会自动进行文件完整性校验，对于大文件该过程可能需要较长时间，若不愿等待可直接退出

#### 查看文件元数据

```bash
python -m BiliOpen info [-h] meta

# meta: META URL(通常以biliopen://开头)
```

#### 查看历史记录

```bash
python -m BiliOpen history [-h]
```

#### 交互模式

不传入任何命令行参数，直接运行程序即可进入交互模式

该模式下，程序会打印命令提示符`BiliOpen > `，并等待用户输入命令

## 应用示例

### 文件备份工具
```python
import BiliOpen
import os

def backup_file(file_path):
    """备份单个文件到B站"""
    if not os.path.exists(file_path):
        print(f"文件不存在: {file_path}")
        return None
    
    print(f"备份文件: {file_path}")
    meta_url = BiliOpen.upload(file_path)
    
    if meta_url:
        print(f"备份成功: {meta_url}")
        return meta_url
    else:
        print("备份失败")
        return None

def restore_file(meta_url, output_path):
    """从B站恢复文件"""
    print(f"恢复文件到: {output_path}")
    result = BiliOpen.download(meta_url, output_path)
    
    if result:
        print("恢复成功")
        return result
    else:
        print("恢复失败")
        return None

# 使用示例
meta_url = backup_file("important_document.pdf")
if meta_url:
    restore_file(meta_url, "restored_document.pdf")
```

### 云存储服务
```python
import BiliOpen

class CloudStorage:
    def __init__(self):
        self.api = BiliOpen.BiliOpenAPI()
    
    def save(self, name: str, data: bytes) -> str:
        """保存数据到云端"""
        meta_url = self.api.upload_bytes(data, name)
        if not meta_url:
            raise Exception("保存失败")
        return meta_url
    
    def load(self, meta_url: str) -> bytes:
        """从云端加载数据"""
        data = self.api.download_bytes(meta_url)
        if not data:
            raise Exception("加载失败")
        return data
    
    def get_info(self, meta_url: str) -> dict:
        """获取文件信息"""
        info = self.api.get_file_info(meta_url)
        if not info:
            raise Exception("获取信息失败")
        return info

# 使用示例
storage = CloudStorage()

# 保存数据
data = b"Important data to store"
meta_url = storage.save("my_data.bin", data)
print(f"已保存: {meta_url}")

# 加载数据
loaded_data = storage.load(meta_url)
print(f"已加载: {loaded_data}")

# 获取信息
info = storage.get_info(meta_url)
print(f"文件信息: {info}")
```

## 技术实现

将任意文件分块编码为图片后上传至B站，对该操作逆序即可下载并还原文件

## 参数调优建议

- `block_size_mb`: 较大的分块适合大文件和良好的网络环境，建议4-8MB
- `thread_count`: 增加线程数可以提高速度，但过多可能导致限流
  - 上传建议使用4-8个线程
  - 下载建议使用8-16个线程

## 性能指标

### 测试文件1

>原作者测试

文件名：[Vmoe]Hatsune Miku「Magical Mirai 2017」[BDrip][1920x1080p][HEVC_YUV420p10_60fps_2FLAC_5.1ch&2.0ch_Chapter][Effect Subtitles].mkv

大小：14.5 GB (14918.37 MB)

分块：10 MB * 1492

META URL：bdrive://d28784bff1086450a6c331fb322accccd382228e

### 上传

地理位置：四川成都

运营商：教育网

上行速率：20 Mbps

用时：02:16:39

平均速度：1.82 MB/s

### 下载

#### 测试点1

地理位置：福建福州

运营商：中国电信

下行速率：100 Mbps

用时：00:18:15

平均速度：13.62 MB/s

#### 测试点2

地理位置：上海

运营商：中国电信

下行速率：1 Gbps

用时：00:02:22

平均速度：104.97 MB/s

### 测试文件2

文件名：test.iso

大小: 5.91 GB

分块: 6 MB * 1009

META URL: biliopen://96f1cad8d8674750cd6592a28b162c4e91b7e4fa

### 上传

地理位置：新加坡   microsoft.com

运营商：Microsoft Azure

平均速度：3.06 MB/s

## 注意事项

1. 请遵守B站的使用条款，不要上传违规内容
2. 大文件上传可能需要较长时间，请耐心等待
3. 建议定期备份重要的META URL
4. Cookie有效期有限，失效时需要重新获取
5. 请自行对重要文件做好本地备份

## 免责声明

请自行对重要文件做好本地备份

请勿使用本项目上传不符合社会主义核心价值观的文件

请合理使用本项目，避免对哔哩哔哩的存储与带宽资源造成无意义的浪费

该项目仅用于学习和技术交流，开发者不承担任何由使用者的行为带来的法律责任

## 许可证

BiliOpen is under The Star And Thank Author License (SATA)

本项目基于MIT协议发布，并增加了SATA协议

您有义务为此开源项目点赞，并考虑额外给予作者适当的奖励 ∠( ᐛ 」∠)＿
