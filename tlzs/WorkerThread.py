import base64
import binascii
import hashlib
import hmac
import io
import json
import psutil
from tqdm import tqdm
from multiprocessing import Pool, sharedctypes
import multiprocessing
import os
import re
from Crypto.Cipher import DES3
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
from PyQt5.QtCore import QThread, pyqtSignal
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from gmssl.sm4 import CryptSM4, SM4_DECRYPT


class CustomBytesOutput(io.StringIO):
    def __init__(self, queue):
        super().__init__()
        self.queue = queue

    def write(self, message):
        if 'Processing items' in message and '%' in message:
            message_log(int(re.search(r'(\d+)%', message).group(1)), message.split('| ')[1], self.queue)


def is_valid_json(json_string):
    try:
        # 尝试将字符串解析为 JSON 对象
        json.loads(json_string)
        return True

    except json.JSONDecodeError:
        return False


def init(arr):
    global shared_all_file
    shared_all_file = arr  # 初始化全局共享数组


def sm4_decrypt_ecb(key, ciphertext, text_know, text_know_type):
    try:
        crypt_sm4 = CryptSM4(padding_mode=0)  # 默认填充为”3-PKCS7“
        crypt_sm4.set_key(key, SM4_DECRYPT)
        data = crypt_sm4.crypt_ecb(ciphertext)  # bytes类型
    except:
        return False

    try:
        padding = 'pkcs7'
        data = unpad(data, AES.block_size)
        if text_know_type == 'json格式':
            if not is_valid_json(data.decode()):
                raise ValueError()

        if text_know and text_know.encode() not in data and text_know.encode(
                "gbk") not in data:
            raise ValueError()

        try:
            return f'模式：sm4_ebc_{padding}' + '\n' + f'明文(utf-8)：{data.decode()}' + '\n' + f'key(二进制)：{key}'
        except UnicodeDecodeError:
            if text_know_type == '明文格式':
                raise ValueError()
            return f'模式：sm4_ebc_{padding}' + '\n' + f'明文(二进制)：{data}' + '\n' + f'key(二进制)：{key}'
    except:
        pass

    try:
        padding = 'zero'
        data = data.rstrip(b'\0')
        if text_know_type == 'json格式':
            if not is_valid_json(data.decode()):
                raise ValueError()
        if text_know and text_know.encode() not in data and text_know.encode(
                "gbk") not in data:
            raise ValueError()

        try:
            return f'模式：sm4_ebc_{padding}' + '\n' + f'明文(utf-8)：{data.decode()}' + '\n' + f'key(二进制)：{key}'
        except UnicodeDecodeError:
            if text_know_type == '明文格式':
                raise ValueError()
            return f'模式：sm4_ebc_{padding}' + '\n' + f'明文(二进制)：{data}' + '\n' + f'key(二进制)：{key}'

    except:
        return False


def sm4_decrypt_cbc(key, ciphertext, iv, text_know, text_know_type):
    is_use_cbc = False
    try:
        crypt_sm4 = CryptSM4(padding_mode=0)
        crypt_sm4.set_key(key, SM4_DECRYPT)
        data = crypt_sm4.crypt_cbc(iv, ciphertext)  #  bytes类型
    except:
        return [False, is_use_cbc]
    try:
        padding = 'pkcs7'
        data = unpad(data, AES.block_size)
        if text_know_type == 'json格式':
            if not is_valid_json(data.decode()):
                raise ZeroDivisionError()
        if text_know_type == '明文格式':
            for i in range(4):
                try:
                    data[16 + i:].decode()
                    is_use_cbc = True
                    break
                except UnicodeDecodeError:
                    pass
            if not is_use_cbc:
                raise ValueError()
        if text_know and text_know.encode() not in data and text_know.encode(
                "gbk") not in data:
            raise ZeroDivisionError()

        is_use_cbc = True
        try:
            return [
                f'模式：sm4_cbc_{padding}' + '\n' + f'明文(utf-8)：{data.decode()}' + '\n' + f'key(二进制)：{key}' + '\n' + f'iv（二进制）：{iv}',
                is_use_cbc]
        except UnicodeDecodeError:
            if text_know_type == '明文格式':
                raise ZeroDivisionError()
            return [
                f'模式：sm4_cbc_{padding}' + '\n' + f'明文(二进制)：{data}' + '\n' + f'key(二进制)：{key}' + '\n' + f'iv（二进制）：{iv}',
                is_use_cbc]
    except ZeroDivisionError:
        is_use_cbc = True
    except:
        pass

    try:
        padding = 'zero'
        data = data.rstrip(b'\0')
        if text_know_type == 'json格式':
            if not is_valid_json(data.decode()):
                raise ZeroDivisionError()
        if text_know_type == '明文格式':
            for i in range(4):
                try:
                    data[16 + i:].decode()
                    is_use_cbc = True
                    break
                except UnicodeDecodeError:
                    pass
            if not is_use_cbc:
                raise ValueError()
        if text_know and text_know.encode() not in data and text_know.encode(
                "gbk") not in data:
            raise ZeroDivisionError()
        is_use_cbc = True
        try:
            return [
                f'模式：sm4_cbc_{padding}' + '\n' + f'明文(utf-8)：{data.decode()}' + '\n' + f'key(二进制)：{key}' + '\n' + f'iv（二进制）：{iv}',
                is_use_cbc]
        except UnicodeDecodeError:
            if text_know_type == '明文格式':
                raise ZeroDivisionError()
            return [
                f'模式：sm4_cbc_{padding}' + '\n' + f'明文(二进制)：{data}' + '\n' + f'key(二进制)：{key}' + '\n' + f'iv（二进制）：{iv}',
                is_use_cbc]

    except ZeroDivisionError:
        is_use_cbc = True
    except:
        pass
    return [False, is_use_cbc]


def aes_decrypt_ecb(key, ciphertext, text_know, text_know_type):
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        data = cipher.decrypt(ciphertext)
    except:
        return False

    try:
        padding = 'pkcs7'
        data = unpad(data, AES.block_size)
        if text_know_type == 'json格式':
            if not is_valid_json(data.decode()):
                raise ValueError()
        if text_know and text_know.encode() not in data and text_know.encode(
                "gbk") not in data:
            raise ValueError()
        try:
            return f'模式：aes_ebc_{padding}' + '\n' + f'明文(utf-8)：{data.decode()}' + '\n' + f'key(二进制)：{key}'
        except UnicodeDecodeError:
            if text_know_type == '明文格式':
                raise ValueError()
            return f'模式：aes_ebc_{padding}' + '\n' + f'明文(二进制)：{data}' + '\n' + f'key(二进制)：{key}'
    except:
        pass
    try:
        padding = 'zero'
        data = data.rstrip(b'\0')
        if text_know_type == 'json格式':
            if not is_valid_json(data.decode()):
                raise ValueError()
        if text_know and text_know.encode() not in data and text_know.encode(
                "gbk") not in data:
            raise ValueError()
        try:
            return f'模式：aes_ebc_{padding}' + '\n' + f'明文(utf-8)：{data.decode()}' + '\n' + f'key(二进制)：{key}'
        except UnicodeDecodeError:
            if text_know_type == '明文格式':
                raise ValueError()
            return f'模式：aes_ebc_{padding}' + '\n' + f'明文(二进制)：{data}' + '\n' + f'key(二进制)：{key}'
    except:
        return False


def aes_decrypt_cbc(key, ciphertext, iv, text_know, text_know_type):
    is_use_cbc = False
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        data = cipher.decrypt(ciphertext)
    except:
        return [False, is_use_cbc]

    try:
        padding = 'pkcs7'
        data = unpad(data, AES.block_size)
        if text_know_type == 'json格式':
            if not is_valid_json(data.decode()):
                raise ZeroDivisionError()
        if text_know_type == '明文格式':
            for i in range(4):
                try:
                    data[16 + i:].decode()
                    is_use_cbc = True
                    break
                except UnicodeDecodeError:
                    pass
            if not is_use_cbc:
                raise ValueError()

        if text_know and text_know.encode() not in data and text_know.encode(
                "gbk") not in data:
            raise ZeroDivisionError()

        is_use_cbc = True
        try:
            return [
                f'模式：aes_cbc_{padding}' + '\n' + f'明文(utf-8)：{data.decode()}' + '\n' + f'key(二进制)：{key}' + '\n' + f'iv（二进制）：{iv}',
                is_use_cbc]
        except UnicodeDecodeError:
            if text_know_type == '明文格式':
                raise ZeroDivisionError()
            return [
                f'模式：aes_cbc_{padding}' + '\n' + f'明文(二进制)：{data}' + '\n' + f'key(二进制)：{key}' + '\n' + f'iv（二进制）：{iv}',
                is_use_cbc]
    except ZeroDivisionError:
        is_use_cbc = True
    except:
        pass

    try:
        padding = 'zero'
        data = data.rstrip(b'\0')
        if text_know_type == 'json格式':
            if not is_valid_json(data.decode()):
                raise ZeroDivisionError()
        if text_know_type == '明文格式':
            for i in range(4):
                try:
                    data[16 + i:].decode()
                    is_use_cbc = True
                    break
                except UnicodeDecodeError:
                    pass
            if not is_use_cbc:
                raise ValueError()

        if text_know and text_know.encode() not in data and text_know.encode(
                "gbk") not in data:
            raise ZeroDivisionError()

        is_use_cbc = True
        try:
            return [
                f'模式：aes_cbc_{padding}' + '\n' + f'明文(utf-8)：{data.decode()}' + '\n' + f'key(二进制)：{key}' + '\n' + f'iv（二进制）：{iv}',
                is_use_cbc]
        except UnicodeDecodeError:
            if text_know_type == '明文格式':
                raise ZeroDivisionError()
            return [
                f'模式：aes_cbc_{padding}' + '\n' + f'明文(二进制)：{data}' + '\n' + f'key(二进制)：{key}' + '\n' + f'iv（二进制）：{iv}',
                is_use_cbc]
    except ZeroDivisionError:
        is_use_cbc = True
    except:
        pass

    return [False, is_use_cbc]


#

def des_decrypt_ecb(key, ciphertext, text_know, text_know_type):
    try:
        cipher = DES.new(key, DES.MODE_ECB)
        data = cipher.decrypt(ciphertext)
    except:
        return False

    try:
        padding = 'pkcs7'
        data = unpad(data, DES.block_size)
        if text_know_type == 'json格式':
            if not is_valid_json(data.decode()):
                raise ValueError()

        if text_know and text_know.encode() not in data and text_know.encode(
                "gbk") not in data:
            raise ValueError()
        try:
            return f'模式：des_ebc_{padding}' + '\n' + f'明文(utf-8)：{data.decode()}' + '\n' + f'key(二进制)：{key}'
        except UnicodeDecodeError:
            if text_know_type == '明文格式':
                raise ValueError()
            return f'模式：des_ebc_{padding}' + '\n' + f'明文(二进制)：{data}' + '\n' + f'key(二进制)：{key}'
    except:
        pass
    try:
        padding = 'zero'
        data = data.rstrip(b'\0')
        if text_know_type == 'json格式':
            if not is_valid_json(data.decode()):
                raise ValueError()

        if text_know and text_know.encode() not in data and text_know.encode(
                "gbk") not in data:
            raise ValueError()
        try:
            return f'模式：des_ebc_{padding}' + '\n' + f'明文(utf-8)：{data.decode()}' + '\n' + f'key(二进制)：{key}'
        except UnicodeDecodeError:
            if text_know_type == '明文格式':
                raise ValueError()
            return f'模式：des_ebc_{padding}' + '\n' + f'明文(二进制)：{data}' + '\n' + f'key(二进制)：{key}'
    except:
        return False


def des_decrypt_cbc(key, ciphertext, iv, text_know, text_know_type):
    is_use_cbc = False
    try:
        cipher = DES.new(key, DES.MODE_CBC, iv)
        data = cipher.decrypt(ciphertext)
    except:
        return [False, is_use_cbc]

    try:
        padding = 'pkcs7'
        data = unpad(data, DES.block_size)
        if text_know_type == 'json格式':
            if not is_valid_json(data.decode()):
                raise ZeroDivisionError()
        if text_know_type == '明文格式':
            for i in range(4):
                try:
                    data[16 + i:].decode()
                    is_use_cbc = True
                    break
                except UnicodeDecodeError:
                    pass
            if not is_use_cbc:
                raise ValueError()
        if text_know and text_know.encode() not in data and text_know.encode(
                "gbk") not in data:
            raise ZeroDivisionError()
        is_use_cbc = True
        try:
            return [
                f'模式：des_cbc_{padding}' + '\n' + f'明文(utf-8)：{data.decode()}' + '\n' + f'key(二进制)：{key}' + '\n' + f'iv（二进制）：{iv}',
                is_use_cbc]
        except UnicodeDecodeError:
            if text_know_type == '明文格式':
                raise ZeroDivisionError()
            return [
                f'模式：des_cbc_{padding}' + '\n' + f'明文(二进制)：{data}' + '\n' + f'key(二进制)：{key}' + '\n' + f'iv（二进制）：{iv}',
                is_use_cbc]
    except ZeroDivisionError:
        is_use_cbc = True
    except:
        pass
    try:
        padding = 'zero'
        data = data.rstrip(b'\0')
        if text_know_type == 'json格式':
            if not is_valid_json(data.decode()):
                raise ZeroDivisionError()
        if text_know_type == '明文格式':
            for i in range(4):
                try:
                    data[16 + i:].decode()
                    is_use_cbc = True
                    break
                except UnicodeDecodeError:
                    pass
            if not is_use_cbc:
                raise ValueError()
        if text_know and text_know.encode() not in data and text_know.encode(
                "gbk") not in data:
            raise ZeroDivisionError()
        is_use_cbc = True
        try:
            return [
                f'模式：des_cbc_{padding}' + '\n' + f'明文(utf-8)：{data.decode()}' + '\n' + f'key(二进制)：{key}' + '\n' + f'iv（二进制）：{iv}',
                is_use_cbc]
        except UnicodeDecodeError:
            if text_know_type == '明文格式':
                raise ZeroDivisionError()
            return [
                f'模式：des_cbc_{padding}' + '\n' + f'明文(二进制)：{data}' + '\n' + f'key(二进制)：{key}' + '\n' + f'iv（二进制）：{iv}',
                is_use_cbc]
    except ZeroDivisionError:
        is_use_cbc = True
    except:
        pass
    return [False, is_use_cbc]


def triple_des_decrypt_ecb(key, ciphertext, text_know, text_know_type):
    try:
        cipher = DES3.new(key, DES3.MODE_ECB)
        data = cipher.decrypt(ciphertext)
    except:
        return False

    try:
        padding = 'pkcs7'
        data = unpad(data, DES3.block_size)
        if text_know_type == 'json格式':
            if not is_valid_json(data.decode()):
                raise ValueError()

        if text_know and text_know.encode() not in data and text_know.encode(
                "gbk") not in data:
            raise ValueError()
        try:
            return f'模式：3des_ebc_{padding}' + '\n' + f'明文(utf-8)：{data.decode()}' + '\n' + f'key(二进制)：{key}'
        except UnicodeDecodeError:
            if text_know_type == '明文格式':
                raise ValueError()
            return f'模式：3des_ebc_{padding}' + '\n' + f'明文(二进制)：{data}' + '\n' + f'key(二进制)：{key}'
    except:
        pass

    try:
        padding = 'zero'
        data = data.rstrip(b'\0')
        if text_know_type == 'json格式':
            if not is_valid_json(data.decode()):
                raise ValueError()

        if text_know and text_know.encode() not in data and text_know.encode(
                "gbk") not in data:
            raise ValueError()
        try:
            return f'模式：3des_ebc_{padding}' + '\n' + f'明文(utf-8)：{data.decode()}' + '\n' + f'key(二进制)：{key}'
        except UnicodeDecodeError:
            if text_know_type == '明文格式':
                raise ValueError()
            return f'模式：3des_ebc_{padding}' + '\n' + f'明文(二进制)：{data}' + '\n' + f'key(二进制)：{key}'
    except:
        return False


def triple_des_decrypt_cbc(key, ciphertext, iv, text_know, text_know_type):
    is_use_cbc = False
    try:
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        data = cipher.decrypt(ciphertext)
    except:
        return [False, is_use_cbc]

    try:
        padding = 'pkcs7'
        data = unpad(data, DES3.block_size)
        if text_know_type == 'json格式':
            if not is_valid_json(data.decode()):
                raise ZeroDivisionError()
        if text_know_type == '明文格式':
            for i in range(4):
                try:
                    data[16 + i:].decode()
                    is_use_cbc = True
                    break
                except UnicodeDecodeError:
                    pass
            if not is_use_cbc:
                raise ValueError()
        if text_know and text_know.encode() not in data and text_know.encode(
                "gbk") not in data:
            raise ZeroDivisionError()
        is_use_cbc = True
        try:
            return [
                f'模式：3des_cbc_{padding}' + '\n' + f'明文(utf-8)：{data.decode()}' + '\n' + f'key(二进制)：{key}' + '\n' + f'iv（二进制）：{iv}',
                is_use_cbc]
        except UnicodeDecodeError:
            if text_know_type == '明文格式':
                raise ZeroDivisionError()
            return [
                f'模式：3des_cbc_{padding}' + '\n' + f'明文(二进制)：{data}' + '\n' + f'key(二进制)：{key}' + '\n' + f'iv（二进制）：{iv}',
                is_use_cbc]
    except ZeroDivisionError:
        is_use_cbc = True
    except:
        pass

    try:
        padding = 'zero'
        data = data.rstrip(b'\0')
        if text_know_type == 'json格式':
            if not is_valid_json(data.decode()):
                raise ZeroDivisionError()
        if text_know_type == '明文格式':
            for i in range(4):
                try:
                    data[16 + i:].decode()
                    is_use_cbc = True
                    break
                except UnicodeDecodeError:
                    pass
            if not is_use_cbc:
                raise ValueError()
        if text_know and text_know.encode() not in data and text_know.encode(
                "gbk") not in data:
            raise ZeroDivisionError()
        is_use_cbc = True
        try:
            return [
                f'模式：3des_cbc_{padding}' + '\n' + f'明文(utf-8)：{data.decode()}' + '\n' + f'key(二进制)：{key}' + '\n' + f'iv（二进制）：{iv}',
                is_use_cbc]
        except UnicodeDecodeError:
            if text_know_type == '明文格式':
                raise ZeroDivisionError()
            return [
                f'模式：3des_cbc_{padding}' + '\n' + f'明文(二进制)：{data}' + '\n' + f'key(二进制)：{key}' + '\n' + f'iv（二进制）：{iv}',
                is_use_cbc]
    except ZeroDivisionError:
        is_use_cbc = True
    except:
        pass
    return [False, is_use_cbc]


def compute_hash(s, hash_algo):
    """根据指定的哈希算法计算字符串的哈希值"""
    hash_obj = hashlib.new(hash_algo)
    hash_obj.update(s)
    return hash_obj.digest()


def compute_hmac(s, key, hash_algo):
    """根据指定的哈希算法和密钥计算 HMAC 值"""
    hmac_obj = hmac.new(key, s, hash_algo)
    return hmac_obj.digest()


def extract_max_multiple_of_4_substring(s):
    length = len(s)
    max_substring = ""

    # 找到最大的长度为4的倍数的子串
    for i in range(length // 4):
        current_length = (i + 1) * 4
        substring = s[:current_length]
        if len(substring) == current_length:
            max_substring = substring

    return max_substring


def detect_format_and_convert_to_binary(s):
    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')

    # 如果符合 hex 格式且长度为偶数（每2个字符表示一个字节）
    if hex_pattern.match(s) and len(s) % 2 == 0:
        try:
            return binascii.unhexlify(s)

        except (binascii.Error, ValueError):
            pass

    # 尝试匹配 Base64 格式（标准的 Base64 字符串只包含A-Z, a-z, 0-9, +, /）
    try:
        base64_bytes = base64.b64decode(s, validate=True)
        if base64.b64encode(base64_bytes).decode('utf-8') == s:
            return base64_bytes
    except (binascii.Error, ValueError):
        pass

    # 默认将其视为明文并转为二进制
    return s.encode('utf-8')


def split_iter(data, delimiter_pattern, pattern, ll):
    # 记录起始位置
    start = 0
    for match in re.finditer(delimiter_pattern, data):

        if bool(re.fullmatch(pattern, data[start:match.start()])):
            if 4 <= len(data[start:match.start()]) < ll:
                yield data[start:match.start()]
        start = match.end()

        # 返回最后一个部分
    if bool(re.fullmatch(pattern, data[start:])):
        if 4 <= len(data[start:]) < ll:
            yield data[start:]


def cpu_bound_hashtask(args):
    key, text_know, text_know_type, algo_input, target_str = args

    if text_know and text_know.encode() not in key and text_know.encode(
            "gbk") not in key:
        return False

    try:
        if text_know_type == 'json格式':
            if not is_valid_json(key.decode()):
                return False
        decoded_str = key.decode('utf-8')
        if compute_hash(decoded_str.encode(), algo_input) == target_str:
            return f"找到匹配的明文(utf-8)：{decoded_str}"

        elif compute_hash(decoded_str.encode("gbk"), algo_input) == target_str:
            return f"找到匹配的明文(gbk)：{decoded_str}"

    except (UnicodeDecodeError, UnicodeEncodeError):
        try:
            if text_know_type == 'json格式':
                if not is_valid_json(key.decode('gbk')):
                    return False
            decoded_str = key.decode('gbk')
            if compute_hash(decoded_str.encode(), algo_input) == target_str:
                return f"找到匹配的明文(utf-8)：{decoded_str}"

            elif compute_hash(decoded_str.encode("gbk"), algo_input) == target_str:
                return f"找到匹配的明文(gbk)：{decoded_str}"

        except (UnicodeDecodeError, UnicodeEncodeError):
            if text_know_type == '明文格式':
                return False
            decoded_str = key
            if compute_hash(decoded_str, algo_input) == target_str:
                return f"找到匹配的明文(二进制)：{key}"


def cpu_bound_hashtask_hmac(args):
    data, pattern_all, text_know, text_know_type, algo_input, target_str = args
    if text_know and text_know.encode() not in data and text_know.encode(
            "gbk") not in data:
        return False
    try:
        if text_know_type == 'json格式':
            if not is_valid_json(data.decode()):
                return False
        decoded_str = data.decode('utf-8')
        for hmac_key in pattern_all.finditer(shared_all_file):
            if compute_hmac(decoded_str.encode(), hmac_key.group(),
                            algo_input) == target_str:
                return f"找到匹配的密钥：{hmac_key.group()}" + '\n' + f"找到匹配的明文(utf-8)：{decoded_str}"
            elif compute_hmac(decoded_str.encode("gbk"), hmac_key.group(),
                              algo_input) == target_str:
                return f"找到匹配的密钥：{hmac_key.group()}" + '\n' + f"找到匹配的明文(gbk)：{decoded_str}"
    except (UnicodeDecodeError, UnicodeEncodeError):
        try:
            if text_know_type == 'json格式':
                if not is_valid_json(data.decode('gbk')):
                    return False
            decoded_str = data.decode('gbk')
            for hmac_key in pattern_all.finditer(shared_all_file):
                if compute_hmac(decoded_str.encode(), hmac_key.group(),
                                algo_input) == target_str:
                    return f"找到匹配的密钥：{hmac_key.group()}" + '\n' + f"找到匹配的明文(utf-8)：{decoded_str}"
                elif compute_hmac(decoded_str.encode("gbk"), hmac_key.group(),
                                  algo_input) == target_str:
                    return f"找到匹配的密钥：{hmac_key.group()}" + '\n' + f"找到匹配的明文(gbk)：{decoded_str}"
        except (UnicodeDecodeError, UnicodeEncodeError):
            if text_know_type == '明文格式':
                return False
            decoded_str = data
            for hmac_key in pattern_all.finditer(shared_all_file):
                if compute_hmac(decoded_str, hmac_key.group(),
                                algo_input) == target_str:
                    return f"找到匹配的密钥：{hmac_key.group()}" + '\n' + f"找到匹配的明文(二进制)：{data}"


def cpu_bound_task_sm4(args):
    key, pattern16, pattern_common_16, pattern_all, is_deep, text_know, text_know_type, target_str = args

    if len(key) >= 16:
        pattern = pattern16 if is_deep else pattern_common_16

    else:
        return False

    for match in pattern.finditer(key):
        ciphertext_ecb = sm4_decrypt_ecb(match.group(1) if is_deep else match.group(0), target_str, text_know,
                                         text_know_type)
        if ciphertext_ecb:
            return ciphertext_ecb

        ciphertext_cbc = sm4_decrypt_cbc(match.group(1) if is_deep else match.group(0), target_str,
                                         b'0123456789abcdef', text_know, text_know_type)

        if ciphertext_cbc[1]:

            for iv in pattern_all.finditer(shared_all_file):
                if len(iv.group()) >= 16:
                    pattern = pattern16 if is_deep else pattern_common_16
                else:
                    continue
                for match_iv in pattern.finditer(iv.group()):
                    ciphertext_cbc = sm4_decrypt_cbc(match.group(1) if is_deep else match.group(0), target_str,
                                                     match_iv.group(1) if is_deep else match_iv.group(0),
                                                     text_know, text_know_type)
                    if ciphertext_cbc[0]:
                        return ciphertext_cbc[0]


def cpu_bound_task_rsa_push(args):
    key = args

    # 原始二进制数据
    binary_data = key
    # 解码为字符串
    text = binary_data.decode('latin1')
    # 使用正则表达式去除尾部的空白字符
    # if not re.search(r'[\s]', text):
    #     text = extract_max_multiple_of_4_substring(text)
    #
    # else:
    text = re.sub(r'[\s]+$', '', text)
    # text = extract_max_multiple_of_4_substring(text)
    text = text.encode('latin1')

    # 尝试将数据作为公钥加载
    try:
        public_key = serialization.load_pem_public_key(
            b'-----BEGIN PUBLIC KEY-----\n' + text + b'\n-----END PUBLIC KEY-----'
        )
        if isinstance(public_key, rsa.RSAPublicKey):
            return "\n这是一个有效的 RSA 公钥。" + '\n' + str(text)
        return False
    except:
        pass  # 如果公钥加载失败，继续尝试私钥
        # 尝试将数据作为私钥加载
    try:
        private_key = serialization.load_pem_private_key(
            b'-----BEGIN RSA PRIVATE KEY-----\n' + text + b'\n-----END RSA PRIVATE KEY-----',
            password=None  # 如果私钥有密码保护，提供密码
        )
        if isinstance(private_key, rsa.RSAPrivateKey):
            return "\n这是一个有效的 RSA 私钥。" + '\n' + str(text)
    except:
        return False


def cpu_bound_task_aes(args):
    key, pattern16, pattern24, pattern_common_24, pattern32, pattern_common_32, pattern_common_16, pattern_all, is_deep, text_know, text_know_type, target_str = args

    if 16 <= len(key) < 24:
        pattern = pattern16 if is_deep else pattern_common_16
    elif 24 <= len(key) < 32:
        pattern = pattern24 if is_deep else pattern_common_24
    elif len(key) >= 32:
        pattern = pattern32 if is_deep else pattern_common_32
    else:
        return False

    for match in pattern.finditer(key):
        ciphertext_ecb = aes_decrypt_ecb(match.group(1) if is_deep else match.group(0), target_str, text_know,
                                         text_know_type)
        if ciphertext_ecb:
            return ciphertext_ecb
        ciphertext_cbc = aes_decrypt_cbc(match.group(1) if is_deep else match.group(0), target_str,
                                         b'0123456789abcdef', text_know, text_know_type)
        if ciphertext_cbc[1]:
            for iv in pattern_all.finditer(shared_all_file):
                if len(iv.group()) >= 16:
                    pattern = pattern16 if is_deep else pattern_common_16
                else:
                    continue
                for match_iv in pattern.finditer(iv.group()):
                    ciphertext_cbc = aes_decrypt_cbc(match.group(1) if is_deep else match.group(0),
                                                     target_str,
                                                     match_iv.group(1) if is_deep else match_iv.group(0),
                                                     text_know, text_know_type)

                    if ciphertext_cbc[0]:
                        return ciphertext_cbc[0]


def cpu_bound_task_des(args):
    key, pattern8, pattern_common_8, pattern_all, is_deep, text_know, text_know_type, target_str = args
    if len(key) >= 8:
        pattern = pattern8 if is_deep else pattern_common_8
    else:
        return False
    for match in pattern.finditer(key):
        ciphertext_ecb = des_decrypt_ecb(match.group(1) if is_deep else match.group(0), target_str, text_know,
                                         text_know_type)
        if ciphertext_ecb:
            return ciphertext_ecb
        ciphertext_cbc = des_decrypt_cbc(match.group(1) if is_deep else match.group(0), target_str,
                                         b'01234567', text_know, text_know_type)
        if ciphertext_cbc[1]:
            for iv in pattern_all.finditer(shared_all_file):
                if len(iv.group()) >= 8:
                    pattern = pattern8 if is_deep else pattern_common_8
                else:
                    continue
                for match_iv in pattern.finditer(iv.group()):
                    ciphertext_cbc = des_decrypt_cbc(match.group(1) if is_deep else match.group(0), target_str,
                                                     match_iv.group(1) if is_deep else match_iv.group(0),
                                                     text_know, text_know_type)

                    if ciphertext_cbc[0]:
                        return ciphertext_cbc[0]


def cpu_bound_task_3des(args):
    key, pattern8, pattern_common_8, pattern16, pattern_common_16, pattern24, pattern_common_24, pattern_all, is_deep, text_know, text_know_type, target_str = args

    if 16 <= len(key) < 24:
        pattern = pattern16 if is_deep else pattern_common_16
    elif len(key) >= 24:
        pattern = pattern24 if is_deep else pattern_common_24

    else:
        return False

    for match in pattern.finditer(key):

        ciphertext_ecb = triple_des_decrypt_ecb(match.group(1) if is_deep else match.group(0), target_str,
                                                text_know, text_know_type)
        if ciphertext_ecb:
            return ciphertext_ecb

        ciphertext_cbc = triple_des_decrypt_cbc(match.group(1) if is_deep else match.group(0), target_str,
                                                b'01234567', text_know, text_know_type)
        if ciphertext_cbc[1]:
            for iv in pattern_all.finditer(shared_all_file):
                if len(iv.group()) >= 8:
                    pattern = pattern8 if is_deep else pattern_common_8
                else:
                    continue

                for match_iv in pattern.finditer(iv.group()):
                    ciphertext_cbc = triple_des_decrypt_cbc(match.group(1) if is_deep else match.group(0),
                                                            target_str,
                                                            match_iv.group(1) if is_deep else match_iv.group(0),
                                                            text_know, text_know_type)
                    if ciphertext_cbc[0]:
                        return ciphertext_cbc[0]


def cpu_bound_task_search_utf8(args):
    key, text_know = args

    try:
        if text_know.encode('utf-8') in key or text_know.encode('gbk') in key:
            return "\n找到明文串(utf-8)\n" + key.decode(
                'utf-8') + '\n' + f"md5值：{hashlib.md5(key).hexdigest()}" + '\n' + f"sha1值：{hashlib.sha1(key).hexdigest()}" + '\n' + f"sha256值：{hashlib.sha256(key).hexdigest()}"
    except UnicodeDecodeError:
        try:
            return "\n找到明文串(gbk编码)\n" + key.decode(
                'gbk') + '\n' + f"md5值：{hashlib.md5(key).hexdigest()}" + '\n' + f"sha1值：{hashlib.sha1(key).hexdigest()}" + '\n' + f"sha256值：{hashlib.sha256(key).hexdigest()}"

        except:
            return False


def find_matching_plaintext(dump_file, target_str, algo_input, use_hmac, text_know, text_know_type, queue, is_deep,
                            is_all_hash=False):
    count_4_totle = dump_file.get('count_4_totle')
    shared_all_file = dump_file.get('shared_all_file')
    pattern_all = re.compile(b'[ -~\x80-\xff]{4,}')
    pattern_common_8 = re.compile(b'[ -~]{8}')
    pattern_common_16 = re.compile(b'[ -~]{16}')
    pattern_common_24 = re.compile(b'[ -~]{24}')
    pattern_common_32 = re.compile(b'[ -~]{32}')
    pattern8 = re.compile(br'(?=(.{8}))')
    pattern16 = re.compile(rb'(?=(.{16}))')
    pattern24 = re.compile(rb'(?=(.{24}))')
    pattern32 = re.compile(rb'(?=(.{32}))')
    message_end(1, queue)
    """在内存转储文件中搜索匹配的明文或密钥"""

    target_str = detect_format_and_convert_to_binary(target_str)

    if algo_input == 'sm4':
        args = ((i.group(), pattern16, pattern_common_16, pattern_all, is_deep, text_know, text_know_type,
                 target_str) for i in
                pattern_all.finditer(shared_all_file))
        output_stream = CustomBytesOutput(queue)
        message_totle(100, queue)
        with Pool(initializer=init, initargs=(shared_all_file,)) as pool:
            for result in tqdm(pool.imap_unordered(cpu_bound_task_sm4, args, 1000),
                               total=count_4_totle,
                               desc="Processing items",
                               file=output_stream):

                if result:
                    send(result, queue)
                    queue.put(algo_input + '_1')
                    return

    if algo_input == 'rsa证书导出':
        isfind = False
        args = ((i.group()) for i in
                re.finditer(rb'M[A-Za-z0-9+/=\s]{128,}', shared_all_file))
        output_stream = CustomBytesOutput(queue)
        message_totle(100, queue)
        with Pool(initializer=init, initargs=(shared_all_file,)) as pool:
            for result in tqdm(pool.imap_unordered(cpu_bound_task_rsa_push, args, 1000),
                               total=count_4_totle,
                               desc="Processing items",
                               file=output_stream):
                if result:
                    isfind = True
                    send(result, queue)
        if isfind:
            return queue.put(algo_input + '_1')

    if algo_input == '明文搜索':
        isfind = False
        args = ((i.group(), text_know) for i in
                re.compile(rb'[\s -~\x80-\xff]{4,}').finditer(shared_all_file))
        output_stream = CustomBytesOutput(queue)
        message_totle(100, queue)
        with Pool(initializer=init, initargs=(shared_all_file,)) as pool:
            for result in tqdm(pool.imap_unordered(cpu_bound_task_search_utf8, args, 1000),
                               total=count_4_totle,
                               desc="Processing items",
                               file=output_stream):
                if result:
                    isfind = True
                    send(result, queue)
        if isfind:
            return queue.put(algo_input + '_1')

    if algo_input == 'aes':
        args = ((i.group(), pattern16, pattern24, pattern_common_24, pattern32, pattern_common_32, pattern_common_16,
                 pattern_all, is_deep, text_know, text_know_type,
                 target_str) for i in
                pattern_all.finditer(shared_all_file))
        output_stream = CustomBytesOutput(queue)
        message_totle(100, queue)
        with Pool(initializer=init, initargs=(shared_all_file,)) as pool:
            for result in tqdm(pool.imap_unordered(cpu_bound_task_aes, args, 1000),
                               total=count_4_totle,
                               desc="Processing items",
                               file=output_stream):
                if result:
                    send(result, queue)
                    queue.put(algo_input + '_1')
                    return

    if algo_input == 'des':

        args = ((i.group(), pattern8, pattern_common_8, pattern_all, is_deep, text_know, text_know_type,
                 target_str) for i in
                pattern_all.finditer(shared_all_file))
        output_stream = CustomBytesOutput(queue)
        message_totle(100, queue)
        with Pool(initializer=init, initargs=(shared_all_file,)) as pool:
            for result in tqdm(pool.imap_unordered(cpu_bound_task_des, args, 1000),
                               total=count_4_totle,
                               desc="Processing items",
                               file=output_stream):
                if result:
                    send(result, queue)
                    queue.put(algo_input + '_1')
                    return

    if algo_input == '3des':
        args = ((i.group(), pattern8, pattern_common_8, pattern16, pattern_common_16, pattern24, pattern_common_24,
                 pattern_all, is_deep, text_know, text_know_type,
                 target_str) for i in
                pattern_all.finditer(shared_all_file))
        output_stream = CustomBytesOutput(queue)
        message_totle(100, queue)
        with Pool(initializer=init, initargs=(shared_all_file,)) as pool:
            for result in tqdm(pool.imap_unordered(cpu_bound_task_3des, args, 1000),
                               total=count_4_totle,
                               desc="Processing items",
                               file=output_stream):
                if result:
                    send(result, queue)
                    queue.put(algo_input + '_1')
                    return

    if algo_input in hashlib.algorithms_available or is_all_hash:

        if is_all_hash:

            for name in ["md5", "sha1", "sha256", "sm3"]:
                algo_input = name
                args = ((i.group(), text_know, text_know_type, algo_input, target_str) for i in
                        pattern_all.finditer(shared_all_file))
                output_stream = CustomBytesOutput(queue)
                message_totle(100, queue)
                with Pool(initializer=init, initargs=(shared_all_file,)) as pool:
                    for result in tqdm(pool.imap_unordered(cpu_bound_hashtask, args, 1000),
                                       total=count_4_totle,
                                       desc="Processing items",
                                       file=output_stream):
                        if result:
                            send(result, queue)
                            queue.put(algo_input + '_1')
                            return

        else:
            if not use_hmac:
                args = ((i.group(), text_know, text_know_type, algo_input, target_str) for i in
                        pattern_all.finditer(shared_all_file))
                output_stream = CustomBytesOutput(queue)
                message_totle(100, queue)
                with Pool(initializer=init, initargs=(shared_all_file,)) as pool:
                    for result in tqdm(pool.imap_unordered(cpu_bound_hashtask, args, 1000),
                                       total=count_4_totle,
                                       desc="Processing items",
                                       file=output_stream):
                        if result:
                            send(result, queue)
                            queue.put(algo_input + '_1')
                            return

            else:
                args = ((i.group(), pattern_all, text_know, text_know_type, algo_input, target_str) for
                        i in
                        pattern_all.finditer(shared_all_file))

                output_stream = CustomBytesOutput(queue)
                message_totle(100, queue)
                with Pool(initializer=init, initargs=(shared_all_file,)) as pool:
                    for result in tqdm(pool.imap_unordered(cpu_bound_hashtask_hmac, args, 1000),
                                       total=count_4_totle,
                                       desc="Processing items",
                                       file=output_stream):

                        if result:
                            send(result, queue)
                            queue.put('hmac' + algo_input + '_1')
                            return

    return queue.put('hmac' + algo_input + '_0' if use_hmac else algo_input + '_0')


def send(message, queue):
    queue.put((1, message))


def message_end(message, queue):
    queue.put((2, message))


def message_log(message, message2, queue):
    queue.put((3, message, message2))


def message_totle(message, queue):
    queue.put((4, message))


class WorkerAllThread(QThread):
    message_changed = pyqtSignal(str)
    message_end = pyqtSignal(int)
    message_log = pyqtSignal(tuple)
    message_totle = pyqtSignal(int)

    def __init__(self, file_path, hash_name, text_know, text_unknow, text_know_type, is_all, is_deep, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.hash_name = hash_name
        self.text_know = text_know
        self.text_unknow = text_unknow
        self.text_know_type = text_know_type
        self.is_all = is_all
        self.is_deep = is_deep
        self.p = None
        self.processes_list = []

    def send(self, message):
        self.message_changed.emit(f"{message}")

    def stop(self):
        try:
            if self.processes_list:
                for processes in self.processes_list:
                    if processes.is_alive():
                        parent_process = psutil.Process(processes.pid)
                        children = parent_process.children(recursive=True)  # 使用 recursive=True 以获取所有子孙进程
                        # 先终止子进程
                        for child in children:
                            if child:
                                try:
                                    child.kill()
                                except Exception as e:
                                    print(e)
                        processes.terminate()
                        processes.join()

            if self.p and self.p.is_alive():
                parent_process = psutil.Process(self.p.pid)
                children = parent_process.children(recursive=True)  # 使用 recursive=True 以获取所有子孙进程
                # 先终止子进程
                for child in children:
                    if child:
                        if child:
                            try:
                                child.kill()
                            except Exception as e:
                                print(e)
                self.p.terminate()
                self.p.join()
        except Exception as e:
            print(e)
    def run(self):
        file_size = os.path.getsize(self.file_path.get('all_files_path'))
        self.file_path['shared_all_file'] = sharedctypes.RawArray('B', file_size)
        with open(self.file_path.get('all_files_path'), 'rb') as file:
            file.readinto(self.file_path.get('shared_all_file'))  # 直接读取到共享数组中
        if self.is_all:
            queue = multiprocessing.Queue()
            self.processes_list = []
            hash_name_list = ["哈希系列", "AES", "DES", "3DES", "SM4"]
            dump_file = self.file_path
            target_hash = self.text_unknow
            for name in hash_name_list:
                # 输入哈希算法类型，允许包含 HMAC 前缀
                algo_input = name.strip().lower()
                # 检查是否使用 HMAC
                use_hmac = algo_input.startswith("hmac")
                if use_hmac:
                    algo_input = algo_input[4:]  # 去掉 "hmac" 前缀
                else:
                    algo_input = algo_input
                pp = multiprocessing.Process(target=find_matching_plaintext, args=(
                    dump_file, target_hash, algo_input, use_hmac, self.text_know, self.text_know_type, queue,
                    self.is_deep,
                    True if name == '哈希系列' else False))
                self.processes_list.append(pp)
                pp.start()
                self.send(f'开启{name}推理进程\n')

            while any(p.is_alive() for p in self.processes_list) or not queue.empty():
                result = queue.get()
                if isinstance(result, tuple):
                    if result[0] == 1:
                        self.send(result[1])
                    elif result[0] == 2:
                        self.message_end.emit(result[1])
                    elif result[0] == 3:
                        self.message_log.emit((result[1], result[2]))
                    elif result[0] == 4:
                        self.message_totle.emit(result[1])
                else:
                    if result.split('_')[1] == '1':
                        self.send(f"*******算法{result.split('_')[0].upper()}匹配成功*******\n")
                        processes = self.processes_list[
                            hash_name_list.index("哈希系列") if result.split('_')[0] in ["md5", "sha1", "sha256",
                                                                                         "sm3"] else hash_name_list.index(
                                result.split('_')[0].upper())]

                        if processes.is_alive():
                            parent_process = psutil.Process(processes.pid)
                            children = parent_process.children(recursive=True)  # 使用 recursive=True 以获取所有子孙进程
                            # 先终止子进程
                            for child in children:
                                if child:
                                    try:
                                        child.kill()
                                    except Exception as e:
                                        print(e)
                            processes.terminate()
                            processes.join()

                    else:
                        self.send(
                            f"*******未找到算法{"HASH系列" if result.split('_')[0] in ["md5", "sha1", "sha256", "sm3"] else result.split('_')[0].upper()}匹配的明文或密钥*******\n")
                        processes = self.processes_list[
                            hash_name_list.index("哈希系列") if result.split('_')[0] in ["md5", "sha1", "sha256",
                                                                                         "sm3"] else hash_name_list.index(
                                result.split('_')[0].upper())]

                        if processes.is_alive():
                            parent_process = psutil.Process(processes.pid)
                            children = parent_process.children(recursive=True)  # 使用 recursive=True 以获取所有子孙进程
                            # 先终止子进程
                            for child in children:
                                if child:
                                    try:
                                        child.kill()
                                    except Exception as e:
                                        print(e)
                            processes.terminate()
                            processes.join()

            self.message_end.emit(0)

        else:
            queue = multiprocessing.Queue()
            dump_file = self.file_path
            target_hash = self.text_unknow
            # 输入哈希算法类型，允许包含 HMAC 前缀
            algo_input = self.hash_name.strip().lower()

            # 检查是否使用 HMAC
            use_hmac = algo_input.startswith("hmac")
            if use_hmac:
                algo_input = algo_input[4:]  # 去掉 "hmac" 前缀
            else:
                algo_input = algo_input

            self.p = multiprocessing.Process(target=find_matching_plaintext, args=(
                dump_file, target_hash, algo_input, use_hmac, self.text_know, self.text_know_type, queue, self.is_deep))
            self.p.start()
            while self.p.is_alive() or not queue.empty():
                result = queue.get()
                if isinstance(result, tuple):
                    if result[0] == 1:
                        self.send(result[1])
                    elif result[0] == 2:
                        self.message_end.emit(result[1])
                    elif result[0] == 3:
                        self.message_log.emit((result[1], result[2]))
                    elif result[0] == 4:
                        self.message_totle.emit(result[1])
                else:

                    if result.split('_')[1] == '1':
                        self.send(f"*******算法{result.split('_')[0]}匹配成功*******\n")
                        if self.p.is_alive():
                            parent_process = psutil.Process(self.p.pid)
                            children = parent_process.children(recursive=True)  # 使用 recursive=True 以获取所有子孙进程
                            # 先终止子进程
                            for child in children:
                                if child:
                                    if child:
                                        try:
                                            child.kill()
                                        except Exception as e:
                                            print(e)
                            self.p.terminate()
                            self.p.join()

                    else:
                        self.send(f"*******未找到算法{result.split('_')[0]}匹配的明文或密钥*******\n")
                        if self.p.is_alive():
                            parent_process = psutil.Process(self.p.pid)
                            children = parent_process.children(recursive=True)  # 使用 recursive=True 以获取所有子孙进程
                            # 先终止子进程
                            for child in children:
                                if child:
                                    if child:
                                        try:
                                            child.kill()
                                        except Exception as e:
                                            print(e)
                            self.p.terminate()
                            self.p.join()

            self.message_end.emit(0)

