import base64
import binascii
import hashlib
import hmac
import json
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

is_use_cbc = False


def is_valid_json(json_string):
    try:
        # 尝试将字符串解析为 JSON 对象
        json.loads(json_string)
        return True
    except json.JSONDecodeError:
        return False


def sm4_decrypt_ecb(key, ciphertext, text_know, text_know_type, queue):
    try:
        crypt_sm4 = CryptSM4(padding_mode=0)  # 默认填充为”3-PKCS7“
        crypt_sm4.set_key(key, SM4_DECRYPT)
        data = crypt_sm4.crypt_ecb(ciphertext)  # bytes类型
        if not data:
            return False
    except:
        return False

    try:
        padding = 'pkcs7'
        data = unpad(data, AES.block_size)
        data = data.decode('utf-8')
        if text_know_type == 'json格式':
            if not is_valid_json(data):
                raise ValueError()
        if text_know and not (text_know in data):
            raise ValueError()

        send(f'模式：sm4_ebc_{padding}', queue)
        send(f'明文：{data}', queue)
        send(f'key(二进制)：{key}', queue)
        return True
    except:
        pass
    try:
        padding = 'zero'
        data = data.rstrip(b'\0')
        data = data.decode('utf-8')
        if text_know_type == 'json格式':
            if not is_valid_json(data):
                raise ValueError()
        if text_know and not (text_know in data):
            raise ValueError()
        send(f'模式：sm4_ebc_{padding}', queue)
        send(f'明文：{data}', queue)
        send(f'key(二进制)：{key}', queue)
        return True
    except:
        return False


def sm4_decrypt_cbc(key, ciphertext, iv, text_know, text_know_type, queue):
    global is_use_cbc
    try:

        crypt_sm4 = CryptSM4(padding_mode=0)
        crypt_sm4.set_key(key, SM4_DECRYPT)
        data = crypt_sm4.crypt_cbc(iv, ciphertext)  #  bytes类型
        if not data:
            return False

    except:
        return False

    try:
        padding = 'pkcs7'

        data = unpad(data, AES.block_size)
        key.decode()
        data = data.decode('utf-8')
        if text_know_type == 'json格式':
            if not is_valid_json(data):
                raise ZeroDivisionError()
        if text_know and not (text_know in data):
            raise ZeroDivisionError("除数不能为零")
        is_use_cbc = True
        send(f'模式：sm4_cbc_{padding}', queue)
        send(f'明文：{data}', queue)
        send(f'key(二进制)：{key}', queue)
        send(f'iv（二进制）：{iv}', queue)
        return True
    except ZeroDivisionError as e:
        is_use_cbc = True
    except:
        pass

    try:
        padding = 'zero'
        data = data.rstrip(b'\0')
        data = data.decode('utf-8')
        if text_know_type == 'json格式':
            if not is_valid_json(data):
                raise ZeroDivisionError()
        if text_know and not (text_know in data):
            raise ZeroDivisionError("除数不能为零")
        is_use_cbc = True
        send(f'模式：sm4_cbc_{padding}', queue)
        send(f'明文：{data}', queue)
        send(f'key(二进制)：{key}', queue)
        send(f'iv（二进制）：{iv}', queue)

        return True
    except ZeroDivisionError as e:
        is_use_cbc = True
    except:
        pass


def aes_decrypt_ecb(key, ciphertext, text_know, text_know_type, queue):
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        data = cipher.decrypt(ciphertext)

    except:
        return False

    try:
        padding = 'pkcs7'
        data = unpad(data, AES.block_size)
        data = data.decode('utf-8')
        if text_know_type == 'json格式':
            if not is_valid_json(data):
                raise ValueError()
        if text_know and not (text_know in data):
            raise ValueError()

        send(f'模式：ase_ebc_{padding}', queue)
        send(f'明文：{data}', queue)
        send(f'key(二进制)：{key}', queue)
        return True
    except:
        pass
    try:
        padding = 'zero'
        data = data.rstrip(b'\0')
        data = data.decode('utf-8')
        if text_know_type == 'json格式':
            if not is_valid_json(data):
                raise ValueError()
        if text_know and not (text_know in data):
            raise ValueError()
        send(f'模式：ase_ebc_{padding}', queue)
        send(f'明文：{data}', queue)
        send(f'key(二进制)：{key}', queue)
        return True
    except:
        return False


def aes_decrypt_cbc(key, ciphertext, iv, text_know, text_know_type, queue):
    global is_use_cbc
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        data = cipher.decrypt(ciphertext)


    except:
        return False

    try:
        padding = 'pkcs7'

        data = unpad(data, AES.block_size)
        data = data.decode('utf-8')
        if text_know_type == 'json格式':
            if not is_valid_json(data):
                raise ZeroDivisionError()
        if text_know and not (text_know in data):
            raise ZeroDivisionError("除数不能为零")
        is_use_cbc = True
        send(f'模式：aes_cbc_{padding}', queue)
        send(f'明文：{data}', queue)
        send(f'key(二进制)：{key}', queue)
        send(f'iv（二进制）：{iv}', queue)
        return True
    except ZeroDivisionError as e:
        is_use_cbc = True
    except:
        pass

    try:
        padding = 'zero'
        data = data.rstrip(b'\0')
        data = data.decode('utf-8')
        if text_know_type == 'json格式':
            if not is_valid_json(data):
                raise ZeroDivisionError()
        if text_know and not (text_know in data):
            raise ZeroDivisionError("除数不能为零")
        is_use_cbc = True
        send(f'模式：aes_cbc_{padding}', queue)
        send(f'明文：{data}', queue)
        send(f'key(二进制)：{key}', queue)
        send(f'iv（二进制）：{iv}', queue)

        return True
    except ZeroDivisionError as e:
        is_use_cbc = True
    except:
        pass


#

def des_decrypt_ecb(key, ciphertext, text_know, text_know_type, queue):
    try:
        cipher = DES.new(key, DES.MODE_ECB)
        data = cipher.decrypt(ciphertext)
    except:
        return False

    try:
        padding = 'pkcs7'
        data = unpad(data, DES.block_size)
        data = data.decode('utf-8')
        if text_know_type == 'json格式':
            if not is_valid_json(data):
                raise ValueError()
        if text_know and not (text_know in data):
            raise ValueError()
        send(f'模式：des_ebc_{padding}', queue)
        send(f'明文：{data}', queue)
        send(f'key(二进制)：{key}', queue)
        return True
    except:
        pass
    try:
        padding = 'zero'
        data = data.rstrip(b'\0')
        data = data.decode('utf-8')
        if text_know_type == 'json格式':
            if not is_valid_json(data):
                raise ValueError()
        if text_know and not (text_know in data):
            raise ValueError()
        send(f'模式：des_ebc_{padding}', queue)
        send(f'明文：{data}', queue)
        send(f'key(二进制)：{key}', queue)
        return True
    except:
        return False


def des_decrypt_cbc(key, ciphertext, iv, text_know, text_know_type, queue):
    global is_use_cbc
    try:
        cipher = DES.new(key, DES.MODE_CBC, iv)
        data = cipher.decrypt(ciphertext)
    except:
        return False

    try:
        padding = 'pkcs7'
        data = unpad(data, DES.block_size)
        data = data.decode('utf-8')
        if text_know_type == 'json格式':
            if not is_valid_json(data):
                raise ZeroDivisionError()
        if text_know and not (text_know in data):
            raise ZeroDivisionError("除数不能为零")
        is_use_cbc = True
        send(f'模式：des_cbc_{padding}', queue)
        send(f'明文：{data}', queue)
        send(f'key(二进制)：{key}', queue)
        send(f'iv（二进制）：{iv}', queue)

        return True
    except ZeroDivisionError as e:
        is_use_cbc = True
    except:
        pass
    try:
        padding = 'zero'
        data = data.rstrip(b'\0')
        data = data.decode('utf-8')
        if text_know_type == 'json格式':
            if not is_valid_json(data):
                raise ZeroDivisionError()
        if text_know and not (text_know in data):
            raise ZeroDivisionError("除数不能为零")
        is_use_cbc = True
        send(f'模式：des_cbc_{padding}', queue)
        send(f'明文：{data}', queue)
        send(f'key(二进制)：{key}', queue)
        send(f'iv（二进制）：{iv}', queue)

        return True
    except ZeroDivisionError as e:
        is_use_cbc = True
    except:
        pass


def triple_des_decrypt_ecb(key, ciphertext, text_know, text_know_type, queue):
    try:
        cipher = DES3.new(key, DES3.MODE_ECB)
        data = cipher.decrypt(ciphertext)
    except:
        return False

    try:
        padding = 'pkcs7'
        data = unpad(data, DES3.block_size)
        data = data.decode('utf-8')
        if text_know_type == 'json格式':
            if not is_valid_json(data):
                raise ValueError()
        if text_know and not (text_know in data):
            raise ValueError()
        send(f'模式：3des_ebc_{padding}', queue)
        send(f'明文：{data}', queue)
        send(f'key(二进制)：{key}', queue)
        return True
    except:
        pass

    try:
        padding = 'zero'
        data = data.rstrip(b'\0')
        data = data.decode('utf-8')
        if text_know_type == 'json格式':
            if not is_valid_json(data):
                raise ValueError()
        if text_know and not (text_know in data):
            raise ValueError()
        send(f'模式：3des_ebc_{padding}', queue)
        send(f'明文：{data}', queue)
        send(f'key(二进制)：{key}', queue)
        return True
    except:
        return False


def triple_des_decrypt_cbc(key, ciphertext, iv, text_know, text_know_type, queue):
    global is_use_cbc
    try:

        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        data = cipher.decrypt(ciphertext)

    except:
        return False

    try:
        padding = 'pkcs7'
        data = unpad(data, DES3.block_size)
        data = data.decode('utf-8')
        if text_know_type == 'json格式':
            if not is_valid_json(data):
                raise ZeroDivisionError()
        if text_know and not (text_know in data):
            raise ZeroDivisionError("除数不能为零")
        is_use_cbc = True
        send(f'模式：3des_cbc_{padding}', queue)
        send(f'明文：{data}', queue)
        send(f'key(二进制)：{key}', queue)
        send(f'iv（二进制）：{iv}', queue)

        return True
    except ZeroDivisionError as e:
        is_use_cbc = True
    except:
        pass

    try:
        padding = 'zero'
        data = data.rstrip(b'\0')
        data = data.decode('utf-8')
        if text_know_type == 'json格式':
            if not is_valid_json(data):
                raise ZeroDivisionError()
        if text_know and not (text_know in data):
            raise ZeroDivisionError("除数不能为零")
        is_use_cbc = True
        send(f'模式：3des_cbc_{padding}', queue)
        send(f'明文：{data}', queue)
        send(f'key(二进制)：{key}', queue)
        send(f'iv（二进制）：{iv}', queue)

        return True
    except ZeroDivisionError as e:
        is_use_cbc = True
    except:
        pass


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


def find_matching_plaintext(dump_file, target_str, algo_input, use_hmac, text_know, text_know_type, queue, is_deep,
                            is_all_hash=False):
    global is_use_cbc
    count_4_totle = dump_file.get('count_4_totle')
    with open(dump_file.get('all_files_path'), 'rb') as file:
        all_files = file.read()
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

        message_totle(count_4_totle, queue)
        for i, key in enumerate(pattern_all.finditer(all_files)):
            if (i + 1) % max(1, count_4_totle // 100) == 0 or i == count_4_totle - 1:
                message_log(i + 1, count_4_totle, queue)  # 批量更新进度条

            if len(key.group()) >= 16:
                pattern = pattern16 if is_deep else pattern_common_16

            else:
                continue

            for match in pattern.finditer(key.group()):
                ciphertext_ecb = sm4_decrypt_ecb(match.group(1) if is_deep else match.group(0), target_str, text_know,
                                                 text_know_type, queue)
                if ciphertext_ecb:
                    return queue.put(algo_input + '_1')

                is_use_cbc = False
                sm4_decrypt_cbc(match.group(1) if is_deep else match.group(0), target_str,
                                b'0123456789abcdef', text_know, text_know_type, queue)

                if is_use_cbc:
                    send('开始推理iv', queue)

                    for iv in pattern_all.finditer(all_files):
                        if len(iv.group()) >= 16:
                            pattern = pattern16 if is_deep else pattern_common_16
                        else:
                            continue

                        for match_iv in pattern.finditer(iv.group()):
                            ciphertext_cbc = sm4_decrypt_cbc(match.group(1) if is_deep else match.group(0), target_str,
                                                             match_iv.group(1) if is_deep else match_iv.group(0),
                                                             text_know, text_know_type, queue)
                            if ciphertext_cbc:
                                return queue.put(algo_input + '_1')

    if algo_input == 'rsa证书导出':

        strings = re.finditer(rb'M[A-Za-z0-9+/=\s]{128,}', all_files)

        isfind = False
        message_totle(0, queue)
        for key in strings:
            message_log(0, 0, queue)  # 批量更新进度条

            # 原始二进制数据
            binary_data = key.group()
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
                    isfind = True
                    send("\n这是一个有效的 RSA 公钥。", queue)
                    send(text, queue)
                continue
            except:

                pass  # 如果公钥加载失败，继续尝试私钥

                # 尝试将数据作为私钥加载
            try:
                private_key = serialization.load_pem_private_key(
                    b'-----BEGIN RSA PRIVATE KEY-----\n' + text + b'\n-----END RSA PRIVATE KEY-----',
                    password=None  # 如果私钥有密码保护，提供密码
                )
                if isinstance(private_key, rsa.RSAPrivateKey):
                    isfind = True
                    send("\n这是一个有效的 RSA 私钥。", queue)
                    send(text, queue)

            except:

                pass
        if isfind:
            return queue.put(algo_input + '_1')
    if algo_input == '明文搜索':
        isfind = False
        message_totle(count_4_totle, queue)
        for i, key in enumerate(re.compile(rb'[\s -~\x80-\xff]{4,}').finditer(all_files)):
            if (i + 1) % max(1, count_4_totle // 100) == 0 or i == count_4_totle - 1:
                message_log(i + 1, count_4_totle, queue)  # 批量更新进度条

            try:
                if text_know.encode('utf-8') in key.group() or text_know.encode('gbk') in key.group():
                    send("\n找到明文串\n" + key.group().decode('utf-8'), queue)
                    send(f"md5值：{hashlib.md5(key.group()).hexdigest()}", queue)
                    send(f"sha1值：{hashlib.sha1(key.group()).hexdigest()}", queue)
                    send(f"sha256值：{hashlib.sha256(key.group()).hexdigest()}", queue)
                    isfind = True

            except UnicodeDecodeError:
                try:
                    send("\n找到明文串(gbk编码)\n" + key.group().decode('gbk'), queue)
                    send(f"md5值：{hashlib.md5(key.group()).hexdigest()}", queue)
                    send(f"sha1值：{hashlib.sha1(key.group()).hexdigest()}", queue)
                    send(f"sha256值：{hashlib.sha256(key.group()).hexdigest()}", queue)
                    isfind = True
                except:
                    pass

        if isfind:
            return queue.put(algo_input + '_1')

    if algo_input == 'aes':

        message_totle(count_4_totle, queue)
        for i, key in enumerate(pattern_all.finditer(all_files)):
            if (i + 1) % max(1, count_4_totle // 100) == 0 or i == count_4_totle - 1:
                message_log(i + 1, count_4_totle, queue)  # 批量更新进度条

            if 16 <= len(key.group()) < 24:
                pattern = pattern16 if is_deep else pattern_common_16
            elif 24 <= len(key.group()) < 32:
                pattern = pattern24 if is_deep else pattern_common_24
            elif len(key.group()) >= 32:
                pattern = pattern32 if is_deep else pattern_common_32
            else:
                continue

            for match in pattern.finditer(key.group()):
                ciphertext_ecb = aes_decrypt_ecb(match.group(1) if is_deep else match.group(0), target_str, text_know,
                                                 text_know_type, queue)
                if ciphertext_ecb:
                    return queue.put(algo_input + '_1')

                is_use_cbc = False
                aes_decrypt_cbc(match.group(1) if is_deep else match.group(0), target_str,
                                b'0123456789abcdef', text_know, text_know_type, queue)

                if is_use_cbc:
                    send('开始推理iv', queue)

                    for iv in pattern_all.finditer(all_files):
                        if len(iv.group()) >= 16:
                            pattern = pattern16 if is_deep else pattern_common_16
                        else:
                            continue

                        for match_iv in pattern.finditer(iv.group()):

                            ciphertext_cbc = aes_decrypt_cbc(match.group(1) if is_deep else match.group(0),
                                                             target_str,
                                                             match_iv.group(1) if is_deep else match_iv.group(0),
                                                             text_know, text_know_type, queue)

                            if ciphertext_cbc:
                                return queue.put(algo_input + '_1')

    if algo_input == 'des':
        message_totle(count_4_totle, queue)
        for i, key in enumerate(pattern_all.finditer(all_files)):
            if (i + 1) % max(1, count_4_totle // 100) == 0 or i == count_4_totle - 1:
                message_log(i + 1, count_4_totle, queue)  # 批量更新进度条

            if len(key.group()) >= 8:
                pattern = pattern8 if is_deep else pattern_common_8
            else:
                continue

            for match in pattern.finditer(key.group()):
                ciphertext_ecb = des_decrypt_ecb(match.group(1) if is_deep else match.group(0), target_str, text_know,
                                                 text_know_type, queue)
                if ciphertext_ecb:
                    return queue.put(algo_input + '_1')

                is_use_cbc = False
                des_decrypt_cbc(match.group(1) if is_deep else match.group(0), target_str,
                                b'01234567', text_know, text_know_type, queue)
                if is_use_cbc:
                    send('开始推理iv', queue)

                    for iv in pattern_all.finditer(all_files):
                        if len(iv.group()) >= 8:
                            pattern = pattern8 if is_deep else pattern_common_8
                        else:
                            continue

                        for match_iv in pattern.finditer(iv.group()):

                            ciphertext_cbc = des_decrypt_cbc(match.group(1) if is_deep else match.group(0), target_str,
                                                             match_iv.group(1) if is_deep else match_iv.group(0),
                                                             text_know, text_know_type, queue)
                            if ciphertext_cbc:
                                return queue.put(algo_input + '_1')

    if algo_input == '3des':

        message_totle(count_4_totle, queue)
        for i, key in enumerate(pattern_all.finditer(all_files)):
            if (i + 1) % max(1, count_4_totle // 100) == 0 or i == count_4_totle - 1:
                message_log(i + 1, count_4_totle, queue)  # 批量更新进度条

            if 16 <= len(key.group()) < 24:
                pattern = pattern16 if is_deep else pattern_common_16
            elif len(key.group()) >= 24:
                pattern = pattern24 if is_deep else pattern_common_24

            else:
                continue

            for match in pattern.finditer(key.group()):

                ciphertext_ecb = triple_des_decrypt_ecb(match.group(1) if is_deep else match.group(0), target_str,
                                                        text_know, text_know_type, queue)
                if ciphertext_ecb:
                    return queue.put(algo_input + '_1')

                is_use_cbc = False

                triple_des_decrypt_cbc(match.group(1) if is_deep else match.group(0), target_str,
                                       b'01234567', text_know, text_know_type, queue)
                if is_use_cbc:
                    send('开始推理iv', queue)
                    for iv in pattern_all.finditer(all_files):

                        if len(iv.group()) >= 8:
                            pattern = pattern8 if is_deep else pattern_common_8
                        else:
                            continue

                        for match_iv in pattern.finditer(iv.group()):
                            ciphertext_cbc = triple_des_decrypt_cbc(match.group(1) if is_deep else match.group(0),
                                                                    target_str,
                                                                    match_iv.group(1) if is_deep else match_iv.group(0),
                                                                    text_know, text_know_type, queue)
                            if ciphertext_cbc:
                                return queue.put(algo_input + '_1')

    if algo_input in hashlib.algorithms_available or is_all_hash:

        if is_all_hash:

            for name in ["md5", "sha1", "sha256", "sm3"]:
                algo_input = name

                message_totle(count_4_totle, queue)
                for i, key in enumerate(pattern_all.finditer(all_files)):
                    if (i + 1) % max(1, count_4_totle // 100) == 0 or i == count_4_totle - 1:
                        message_log(i + 1, count_4_totle, queue)  # 批量更新进度条

                    if text_know and text_know.encode() not in key.group() and text_know.encode(
                            "gbk") not in key.group():
                        continue

                    if compute_hash(key.group(), algo_input) == target_str:
                        try:
                            if text_know_type == 'json格式':
                                if not is_valid_json(key.group().decode()):
                                    continue
                            decoded_str = key.group().decode('utf-8')
                            send(f"找到匹配的明文(utf-8)：{decoded_str}", queue)
                            return queue.put(algo_input + '_1')
                        except UnicodeDecodeError:
                            try:
                                if text_know_type == 'json格式':
                                    if not is_valid_json(key.group().decode('gbk')):
                                        continue
                                decoded_str = key.group().decode('gbk')
                                send(f"找到匹配的明文(gbk)：{decoded_str}", queue)
                                return queue.put(algo_input + '_1')
                            except UnicodeDecodeError:
                                send(f"找到匹配的二进制：{key.group()}", queue)
                                return queue.put(algo_input + '_1')

        else:
            if not use_hmac:
                message_totle(count_4_totle, queue)
                for i, key in enumerate(pattern_all.finditer(all_files)):
                    if (i + 1) % max(1, count_4_totle // 100) == 0 or i == count_4_totle - 1:
                        message_log(i + 1, count_4_totle, queue)  # 批量更新进度条

                    if text_know and text_know.encode() not in key.group() and text_know.encode(
                            "gbk") not in key.group():
                        continue

                    if compute_hash(key.group(), algo_input) == target_str:
                        try:
                            if text_know_type == 'json格式':
                                if not is_valid_json(key.group().decode()):
                                    continue
                            decoded_str = key.group().decode('utf-8')
                            send(f"找到匹配的明文(utf-8)：{decoded_str}", queue)
                            return queue.put(algo_input + '_1')
                        except UnicodeDecodeError:
                            try:
                                if text_know_type == 'json格式':
                                    if not is_valid_json(key.group().decode('gbk')):
                                        continue
                                decoded_str = key.group().decode('gbk')
                                send(f"找到匹配的明文(gbk)：{decoded_str}", queue)
                                return queue.put(algo_input + '_1')
                            except UnicodeDecodeError:
                                send(f"找到匹配的二进制：{key.group()}", queue)
                                return queue.put(algo_input + '_1')


            else:

                message_totle(count_4_totle, queue)
                for i, key in enumerate(pattern_all.finditer(all_files)):
                    if (i + 1) % max(1, count_4_totle // 100) == 0 or i == count_4_totle - 1:
                        message_log(i + 1, count_4_totle, queue)  # 批量更新进度条

                    if text_know and text_know.encode() not in key.group() and text_know.encode(
                            "gbk") not in key.group():
                        continue

                    for hmac_key in pattern_all.finditer(all_files):
                        # 尝试提取的字符串作为密钥，使用已知的消息进行 HMAC 并与目标 HMAC 值比较
                        computed_hmac = compute_hmac(key.group(), hmac_key.group(),
                                                     algo_input)  # 消息是 known_message，密钥是 decoded_str

                        if computed_hmac == target_str:
                            send(f"找到匹配的密钥：{hmac_key.group()}", queue)
                            try:
                                if text_know_type == 'json格式':
                                    if not is_valid_json(key.group().decode()):
                                        continue
                                decoded_str = key.group().decode('utf-8')
                                send(f"找到匹配的明文(utf-8)：{decoded_str}", queue)
                                return queue.put('hmac' + algo_input + '_1')
                            except UnicodeDecodeError:
                                try:
                                    if text_know_type == 'json格式':
                                        if not is_valid_json(key.group().decode('gbk')):
                                            continue
                                    decoded_str = key.group().decode('gbk')
                                    send(f"找到匹配的明文(gbk)：{decoded_str}", queue)
                                    return queue.put('hmac' + algo_input + '_1')
                                except UnicodeDecodeError:
                                    send(f"找到匹配的二进制：{key.group()}", queue)
                                    return queue.put('hmac' + algo_input + '_1')

    return queue.put(algo_input + '_0')


def send(message, queue):
    queue.put((1, message))


def message_end(message, queue):
    queue.put((2, message))


def message_log(message, totle, queue):
    queue.put((3, message, totle))


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
        if self.p:
            self.p.terminate()
            self.p.join()

        if self.processes_list:
            for processes in self.processes_list:
                processes.terminate()
                processes.join()

    def get_file_size_in_mb(self, file_path):
        # 获取文件大小（字节）
        file_size_bytes = os.path.getsize(file_path)
        # 将字节转换为 MB
        file_size_mb = file_size_bytes / (1024 * 1024)
        return int(file_size_mb)

    def run(self):
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
                if self.get_file_size_in_mb('memory_data.bin') < 400:
                    self.p = multiprocessing.Process(target=find_matching_plaintext, args=(
                        dump_file, target_hash, algo_input, use_hmac, self.text_know, self.text_know_type, queue,
                        self.is_deep,
                        True if name == '哈希系列' else False))
                    self.processes_list.append(self.p)
                    self.p.start()
                    self.send(f'开启{name}推理进程\n')

                else:
                    self.message_end.emit(2)
                    self.send('模型较大使用单进程逐个推理\n')
                    self.p = multiprocessing.Process(target=find_matching_plaintext, args=(
                        dump_file, target_hash, algo_input, use_hmac, self.text_know, self.text_know_type, queue,
                        self.is_deep,
                        True if name == '哈希系列' else False))
                    self.processes_list.append(self.p)
                    self.p.start()
                    self.send(f'开启{name}推理进程\n')
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
                                self.p.join()
                            else:
                                self.send(
                                    f"*******未找到算法{"HASH系列" if result.split('_')[0] in ["md5", "sha1", "sha256", "sm3"] else result.split('_')[0].upper()}匹配的明文或密钥*******\n")
                                self.p.join()

            if self.get_file_size_in_mb('memory_data.bin') < 400:
                self.message_end.emit(1)
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
                            self.processes_list[
                                hash_name_list.index("哈希系列") if result.split('_')[0] in ["md5", "sha1", "sha256",
                                                                                             "sm3"] else hash_name_list.index(
                                    result.split('_')[0].upper())].join()
                        else:
                            self.send(
                                f"*******未找到算法{"HASH系列" if result.split('_')[0] in ["md5", "sha1", "sha256", "sm3"] else result.split('_')[0].upper()}匹配的明文或密钥*******\n")
                            self.processes_list[
                                hash_name_list.index("哈希系列") if result.split('_')[0] in ["md5", "sha1", "sha256",
                                                                                             "sm3"] else hash_name_list.index(
                                    result.split('_')[0].upper())].join()

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
                        self.p.join()

                    else:
                        self.send(f"*******未找到算法{result.split('_')[0]}匹配的明文或密钥*******\n")
                        self.p.join()

            self.message_end.emit(0)
