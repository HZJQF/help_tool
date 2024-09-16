import base64
import binascii
import hashlib
import hmac
import io
import json
import re
import threading

from Crypto.Cipher import DES3
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
from PyQt5.QtCore import QThread, pyqtSignal
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from gmssl.sm4 import CryptSM4, SM4_DECRYPT


class WorkerThread(QThread):
    message_changed = pyqtSignal(str)
    message_end = pyqtSignal()
    message_log = pyqtSignal(int)
    message_totle = pyqtSignal(int)

    def __init__(self, file_path, hash_name, text_know, text_unknow, text_know_type, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.hash_name = hash_name
        self.text_know = text_know
        self.text_unknow = text_unknow
        self.text_know_type = text_know_type
        self.is_use_cbc = False


    def is_valid_json(self, json_string):

        try:
            # 尝试将字符串解析为 JSON 对象
            json.loads(json_string)
            return True
        except json.JSONDecodeError:
            return False

    def detect_format_and_convert_to_binary(self, s):
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

    def sm4_decrypt_ecb(self, key, ciphertext):
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
            if self.text_know_type == 'json格式':
                if not self.is_valid_json(data):
                    raise ValueError()
            if self.text_know and not (self.text_know in data):
                raise ValueError()

            self.send(f'模式：sm4_ebc_{padding}')
            self.send(f'明文：{data}')
            self.send(f'key(二进制)：{key}')
            return True
        except:
            pass
        try:
            padding = 'zero'
            data = data.rstrip(b'\0')
            data = data.decode('utf-8')
            if self.text_know_type == 'json格式':
                if not self.is_valid_json(data):
                    raise ValueError()
            if self.text_know and not (self.text_know in data):
                raise ValueError()
            self.send(f'模式：sm4_ebc_{padding}')
            self.send(f'明文：{data}')
            self.send(f'key(二进制)：{key}')
            return True
        except:
            return False

    def sm4_decrypt_cbc(self, key, ciphertext, iv):
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
            if self.text_know_type == 'json格式':
                if not self.is_valid_json(data):
                    raise ZeroDivisionError()
            if self.text_know and not (self.text_know in data):
                raise ZeroDivisionError("除数不能为零")
            self.is_use_cbc = True
            self.send(f'模式：sm4_cbc_{padding}')
            self.send(f'明文：{data}')
            self.send(f'key(二进制)：{key}')
            self.send(f'iv（二进制）：{iv}')
            return True
        except ZeroDivisionError as e:
            self.is_use_cbc = True
        except:
            pass

        try:
            padding = 'zero'
            data = data.rstrip(b'\0')
            data = data.decode('utf-8')
            if self.text_know_type == 'json格式':
                if not self.is_valid_json(data):
                    raise ZeroDivisionError()
            if self.text_know and not (self.text_know in data):
                raise ZeroDivisionError("除数不能为零")
            self.is_use_cbc = True
            self.send(f'模式：sm4_cbc_{padding}')
            self.send(f'明文：{data}')
            self.send(f'key(二进制)：{key}')
            self.send(f'iv（二进制）：{iv}')

            return True
        except ZeroDivisionError as e:
            self.is_use_cbc = True
        except:
            pass


    def aes_decrypt_ecb(self, key, ciphertext):
        try:
            cipher = AES.new(key, AES.MODE_ECB)
            data = cipher.decrypt(ciphertext)

        except:
            return False

        try:
            padding = 'pkcs7'
            data = unpad(data, AES.block_size)
            data = data.decode('utf-8')
            if self.text_know_type == 'json格式':
                if not self.is_valid_json(data):
                    raise ValueError()
            if self.text_know and not (self.text_know in data):
                raise ValueError()

            self.send(f'模式：ase_ebc_{padding}')
            self.send(f'明文：{data}')
            self.send(f'key(二进制)：{key}')
            return True
        except:
            pass
        try:
            padding = 'zero'
            data = data.rstrip(b'\0')
            data = data.decode('utf-8')
            if self.text_know_type == 'json格式':
                if not self.is_valid_json(data):
                    raise ValueError()
            if self.text_know and not (self.text_know in data):
                raise ValueError()
            self.send(f'模式：ase_ebc_{padding}')
            self.send(f'明文：{data}')
            self.send(f'key(二进制)：{key}')
            return True
        except:
            return False

    def aes_decrypt_cbc(self, key, ciphertext, iv):
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            data = cipher.decrypt(ciphertext)


        except:
            return False

        try:
            padding = 'pkcs7'

            data = unpad(data, AES.block_size)
            key.decode()
            data = data.decode('utf-8')
            if self.text_know_type == 'json格式':
                if not self.is_valid_json(data):
                    raise ZeroDivisionError()
            if self.text_know and not (self.text_know in data):
                raise ZeroDivisionError("除数不能为零")
            self.is_use_cbc = True
            self.send(f'模式：aes_cbc_{padding}')
            self.send(f'明文：{data}')
            self.send(f'key(二进制)：{key}')
            self.send(f'iv（二进制）：{iv}')
            return True
        except ZeroDivisionError as e:
            self.is_use_cbc = True
        except:
            pass

        try:
            padding = 'zero'
            data = data.rstrip(b'\0')
            data = data.decode('utf-8')
            if self.text_know_type == 'json格式':
                if not self.is_valid_json(data):
                    raise ZeroDivisionError()
            if self.text_know and not (self.text_know in data):
                raise ZeroDivisionError("除数不能为零")
            self.is_use_cbc = True
            self.send(f'模式：aes_cbc_{padding}')
            self.send(f'明文：{data}')
            self.send(f'key(二进制)：{key}')
            self.send(f'iv（二进制）：{iv}')

            return True
        except ZeroDivisionError as e:
            self.is_use_cbc = True
        except:
            pass



    #

    def des_decrypt_ecb(self, key, ciphertext):
        try:
            cipher = DES.new(key, DES.MODE_ECB)
            data = cipher.decrypt(ciphertext)
        except:
            return False

        try:
            padding = 'pkcs7'
            data = unpad(data, DES.block_size)
            data = data.decode('utf-8')
            if self.text_know_type == 'json格式':
                if not self.is_valid_json(data):
                    raise ValueError()
            if self.text_know and not (self.text_know in data):
                raise ValueError()
            self.send(f'模式：des_ebc_{padding}')
            self.send(f'明文：{data}')
            self.send(f'key(二进制)：{key}')
            return True
        except:
            pass
        try:
            padding = 'zero'
            data = data.rstrip(b'\0')
            data = data.decode('utf-8')
            if self.text_know_type == 'json格式':
                if not self.is_valid_json(data):
                    raise ValueError()
            if self.text_know and not (self.text_know in data):
                raise ValueError()
            self.send(f'模式：des_ebc_{padding}')
            self.send(f'明文：{data}')
            self.send(f'key(二进制)：{key}')
            return True
        except:
            return False

    def des_decrypt_cbc(self, key, ciphertext, iv):

        try:
            cipher = DES.new(key, DES.MODE_CBC, iv)
            data = cipher.decrypt(ciphertext)
        except:
            return False

        try:
            padding = 'pkcs7'
            data = unpad(data, DES.block_size)
            data = data.decode('utf-8')
            if self.text_know_type == 'json格式':
                if not self.is_valid_json(data):
                    raise ZeroDivisionError()
            if self.text_know and not (self.text_know in data):
                raise ZeroDivisionError("除数不能为零")
            self.is_use_cbc = True
            self.send(f'模式：des_cbc_{padding}')
            self.send(f'明文：{data}')
            self.send(f'key(二进制)：{key}')
            self.send(f'iv（二进制）：{iv}')

            return True
        except ZeroDivisionError as e:
            self.is_use_cbc = True
        except:
            pass
        try:
            padding = 'zero'
            data = data.rstrip(b'\0')
            data = data.decode('utf-8')
            if self.text_know_type == 'json格式':
                if not self.is_valid_json(data):
                    raise ZeroDivisionError()
            if self.text_know and not (self.text_know in data):
                raise ZeroDivisionError("除数不能为零")
            self.is_use_cbc = True
            self.send(f'模式：des_cbc_{padding}')
            self.send(f'明文：{data}')
            self.send(f'key(二进制)：{key}')
            self.send(f'iv（二进制）：{iv}')

            return True
        except ZeroDivisionError as e:
            self.is_use_cbc = True
        except:
            pass

    def triple_des_decrypt_ecb(self, key, ciphertext):
        try:
            cipher = DES3.new(key, DES3.MODE_ECB)
            data = cipher.decrypt(ciphertext)
        except:
            return False

        try:
            padding = 'pkcs7'
            data = unpad(data, DES3.block_size)
            data = data.decode('utf-8')
            if self.text_know_type == 'json格式':
                if not self.is_valid_json(data):
                    raise ValueError()
            if self.text_know and not (self.text_know in data):
                raise ValueError()
            self.send(f'模式：3des_ebc_{padding}')
            self.send(f'明文：{data}')
            self.send(f'key(二进制)：{key}')
            return True
        except:
            pass
        try:
            padding = 'zero'
            data = data.rstrip(b'\0')
            data = data.decode('utf-8')
            if self.text_know_type == 'json格式':
                if not self.is_valid_json(data):
                    raise ValueError()
            if self.text_know and not (self.text_know in data):
                raise ValueError()
            self.send(f'模式：3des_ebc_{padding}')
            self.send(f'明文：{data}')
            self.send(f'key(二进制)：{key}')
            return True
        except:
            return False

    def triple_des_decrypt_cbc(self, key, ciphertext, iv):
        try:
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
            data = cipher.decrypt(ciphertext)
        except:
            return False

        try:
            padding = 'pkcs7'
            data = unpad(data, DES3.block_size)
            data = data.decode('utf-8')
            if self.text_know_type == 'json格式':
                if not self.is_valid_json(data):
                    raise ZeroDivisionError()
            if self.text_know and not (self.text_know in data):
                raise ZeroDivisionError("除数不能为零")
            self.is_use_cbc = True
            self.send(f'模式：3des_cbc_{padding}')
            self.send(f'明文：{data}')
            self.send(f'key(二进制)：{key}')
            self.send(f'iv（二进制）：{iv}')

            return True
        except ZeroDivisionError as e:
            self.is_use_cbc = True
        except:
            pass

        try:
            padding = 'zero'
            data = data.rstrip(b'\0')
            data = data.decode('utf-8')
            if self.text_know_type == 'json格式':
                if not self.is_valid_json(data):
                    raise ZeroDivisionError()
            if self.text_know and not (self.text_know in data):
                raise ZeroDivisionError("除数不能为零")
            self.is_use_cbc = True
            self.send(f'模式：3des_cbc_{padding}')
            self.send(f'明文：{data}')
            self.send(f'key(二进制)：{key}')
            self.send(f'iv（二进制）：{iv}')

            return True
        except ZeroDivisionError as e:
            self.is_use_cbc = True
        except:
            pass

    def compute_hash(self, s, hash_algo):
        """根据指定的哈希算法计算字符串的哈希值"""
        hash_obj = hashlib.new(hash_algo)
        hash_obj.update(s.encode())
        return hash_obj.digest()

    def compute_hmac(self, s, key, hash_algo):
        """根据指定的哈希算法和密钥计算 HMAC 值"""
        hmac_obj = hmac.new(key, s.encode(), hash_algo)
        return hmac_obj.digest()

    def process_memory_data(self, memory_data, chunk_size, pattern, tail_length):
        pattern = re.compile(pattern)
        strings = set()

        # 保留的尾部数据长度为 256 字节
        tail_length = tail_length

        previous_chunk_end = b''

        file_stream = io.BytesIO(memory_data)

        while True:
            chunk = file_stream.read(chunk_size)
            if not chunk:
                break

            # 将前一块的尾部与当前块合并
            combined_chunk = previous_chunk_end + chunk

            # 查找匹配项
            matches = pattern.findall(combined_chunk)
            strings.update(matches)

            # 更新前一块的尾部数据
            previous_chunk_end = chunk[-tail_length:] if len(chunk) > tail_length else chunk

        return list(strings)

    def extract_max_multiple_of_4_substring(self, s):
        length = len(s)
        max_substring = ""

        # 找到最大的长度为4的倍数的子串
        for i in range(length // 4):
            current_length = (i + 1) * 4
            substring = s[:current_length]
            if len(substring) == current_length:
                max_substring = substring

        return max_substring

    def find_matching_plaintext(self, dump_file, target_str, algo_input, use_hmac):

        all_files = dump_file.get('all_files')
        dump_file = dump_file.get('strings')

        """在内存转储文件中搜索匹配的明文或密钥"""

        target_str = self.detect_format_and_convert_to_binary(target_str)

        if algo_input == 'sm4':
            pattern16 = re.compile(br'(?=(.{16}))')
            strings16 = []
            for item in dump_file:
                if len(item) >= 16:
                    strings16.extend([match.group(1) for match in pattern16.finditer(item)])
            self.message_totle.emit(len(strings16))
            for i, key in enumerate(strings16):
                if (i + 1) % max(1, len(strings16) // 100) == 0 or i == len(strings16) - 1:
                    self.message_log.emit(i + 1)  # 批量更新进度条

                ciphertext_ecb = self.sm4_decrypt_ecb(key, target_str)
                if ciphertext_ecb:
                    return True

                self.is_use_cbc = False
                self.sm4_decrypt_cbc(key, target_str,
                                     b'0123456789abcdef')
                if self.is_use_cbc:
                    self.send('开始推理iv')

                    for iv in strings16:

                        ciphertext_cbc = self.sm4_decrypt_cbc(key, target_str,
                                                              iv, )
                        if ciphertext_cbc:
                            return True


            pass

        if algo_input == 'rsa证书导出':

            strings = self.process_memory_data(all_files, 1024, rb'M[A-Za-z0-9+/=\s]{128,}', 128)

            isfind = False
            self.message_totle.emit(len(strings))
            for i, key in enumerate(strings):
                if (i + 1) % max(1, len(strings) // 100) == 0 or i == len(strings) - 1:
                    self.message_log.emit(i + 1)  # 批量更新进度条

                # 原始二进制数据
                binary_data = key
                # 解码为字符串
                text = binary_data.decode('latin1')
                # 使用正则表达式去除尾部的空白字符
                if not re.search(r'[\s]', text):
                    text = self.extract_max_multiple_of_4_substring(text)

                else:
                    text = re.sub(r'[\s]+$', '', text)
                text = text.encode('latin1')

                # 尝试将数据作为公钥加载
                try:
                    public_key = serialization.load_pem_public_key(
                        b'-----BEGIN PUBLIC KEY-----\n' + text + b'\n-----END PUBLIC KEY-----'
                    )
                    if isinstance(public_key, rsa.RSAPublicKey):
                        isfind = True
                        self.send("\n这是一个有效的 RSA 公钥。")
                        self.send(text)
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
                        self.send("\n这是一个有效的 RSA 私钥。")
                        self.send(text)

                except:

                    pass
            if isfind:
                return True
        if algo_input == '明文搜索':
            isfind = False
            self.message_totle.emit(len(dump_file))
            for i, key in enumerate(dump_file):
                if (i + 1) % max(1, len(dump_file) // 100) == 0 or i == len(dump_file) - 1:
                    self.message_log.emit(i + 1)  # 批量更新进度条

                try:
                    if self.text_know.encode('utf-8') in key or self.text_know.encode('gbk') in key:

                        self.send("\n找到明文串\n" + key.decode('utf-8'))
                        self.send(f"md5值：{hashlib.md5(key).hexdigest()}")
                        self.send(f"sha1值：{hashlib.sha1(key).hexdigest()}")
                        self.send(f"sha256值：{hashlib.sha256(key).hexdigest()}")
                        isfind = True

                except UnicodeDecodeError:
                    try:
                            self.send("\n找到明文串(gbk编码)\n" + key.decode('gbk'))
                            self.send(f"md5值：{hashlib.md5(key).hexdigest()}")
                            self.send(f"sha1值：{hashlib.sha1(key).hexdigest()}")
                            self.send(f"sha256值：{hashlib.sha256(key).hexdigest()}")
                            isfind = True
                    except:
                        pass

            if isfind:
                return True

        if algo_input == 'aes':
            pattern16 = re.compile(rb'(?=(.{16}))')
            pattern24 = re.compile(rb'(?=(.{24}))')
            pattern32 = re.compile(rb'(?=(.{32}))')

            strings16 = []
            strings24 = []
            strings32 = []
            stringslist = []

            for item in dump_file:
                if 16 <= len(item) < 24:
                    strings16.extend([match.group(1) for match in pattern16.finditer(item)])
                if 24 <= len(item) < 32:
                    strings24.extend([match.group(1) for match in pattern24.finditer(item)])
                if len(item) >= 32:
                    strings32.extend([match.group(1) for match in pattern32.finditer(item)])

            stringslist.extend(strings16)
            stringslist.extend(strings24)
            stringslist.extend(strings32)

            self.message_totle.emit(len(stringslist))
            for i, key in enumerate(stringslist):
                if (i + 1) % max(1, len(stringslist) // 100) == 0 or i == len(stringslist) - 1:
                    self.message_log.emit(i + 1)  # 批量更新进度条

                ciphertext_ecb = self.aes_decrypt_ecb(key, target_str)
                if ciphertext_ecb:
                    return True

                self.is_use_cbc = False
                self.aes_decrypt_cbc(key, target_str,
                                     b'0123456789abcdef')

                if self.is_use_cbc:
                    self.send('开始推理iv')

                    for iv in strings16:

                        ciphertext_cbc = self.aes_decrypt_cbc(key,
                                                              target_str,
                                                              iv)

                        if ciphertext_cbc:
                            return True

        if algo_input == 'des':
            pattern8 = re.compile(br'(?=(.{8}))')
            strings8 = []
            for item in dump_file:
                if len(item) >= 8:
                    strings8.extend([match.group(1) for match in pattern8.finditer(item)])
            self.message_totle.emit(len(strings8))
            for i, key in enumerate(strings8):
                if (i + 1) % max(1, len(strings8) // 100) == 0 or i == len(strings8) - 1:
                    self.message_log.emit(i + 1)  # 批量更新进度条

                ciphertext_ecb = self.des_decrypt_ecb(key, target_str)
                if ciphertext_ecb:
                    return True

                self.is_use_cbc = False
                self.des_decrypt_cbc(key, target_str,
                                     b'01234567')
                if self.is_use_cbc:
                    self.send('开始推理iv')

                    for iv in strings8:

                        ciphertext_cbc = self.des_decrypt_cbc(key, target_str,
                                                              iv, )
                        if ciphertext_cbc:
                            return True

        if algo_input == '3des':
            pattern8 = re.compile(br'(?=(.{8}))')
            pattern24 = re.compile(br'(?=(.{24}))')
            strings8 = []
            strings24 = []

            for item in dump_file:
                if 8 <= len(item) < 24:
                    strings8.extend([match.group(1) for match in pattern8.finditer(item)])

                if len(item) >= 24:
                    strings24.extend([match.group(1) for match in pattern24.finditer(item)])

            self.message_totle.emit(len(strings24))
            for i, key in enumerate(strings24):
                if (i + 1) % max(1, len(strings24) // 100) == 0 or i == len(strings24) - 1:
                    self.message_log.emit(i + 1)  # 批量更新进度条
                ciphertext_ecb = self.triple_des_decrypt_ecb(key, target_str)
                if ciphertext_ecb:
                    return True

                self.is_use_cbc = False

                self.triple_des_decrypt_cbc(key, target_str,
                                            b'00000000')
                if self.is_use_cbc:
                    self.send('开始推理iv')
                    print(len(strings8))
                    for iv in strings8:
                        # print(iv)
                        ciphertext_cbc = self.triple_des_decrypt_cbc(key, target_str, iv)
                        if ciphertext_cbc:
                            return True

        if algo_input in hashlib.algorithms_available:

            strings = dump_file  # 提取较长的可打印字符串，包括中文字符
            stringslist = []

            for s in strings:
                try:
                    if self.text_know_type == 'json格式':
                        if not self.is_valid_json(s.decode()):
                            continue
                    stringslist.append(s.decode('utf-8'))
                except UnicodeDecodeError:
                    try:
                        if self.text_know_type == 'json格式':
                            if not self.is_valid_json(s.decode('gbk')):
                                continue
                        stringslist.append(s.decode('gbk'))
                    except UnicodeDecodeError:
                        continue

            if not use_hmac:

                if self.text_know:
                    known_messagelist = []
                    for mm in stringslist:
                        if self.text_know in mm:
                            known_messagelist.append(mm)

                    self.message_totle.emit(len(known_messagelist))
                    for i, decoded_str in enumerate(known_messagelist):
                        if (i + 1) % max(1, len(known_messagelist) // 20) == 0 or i == len(known_messagelist) - 1:
                            self.message_log.emit(i + 1)  # 批量更新进度条

                        if self.compute_hash(decoded_str, algo_input) == target_str:
                            self.send(f"找到匹配的明文：{decoded_str}")

                            return True
                else:
                    self.message_totle.emit(len(stringslist))
                    for i, decoded_str in enumerate(stringslist):
                        if (i + 1) % max(1, len(stringslist) // 20) == 0 or i == len(stringslist) - 1:
                            self.message_log.emit(i + 1)  # 批量更新进度条

                        if self.compute_hash(decoded_str, algo_input) == target_str:
                            self.send(f"找到匹配的明文：{decoded_str}")

                            return True
            else:
                if not self.text_know:
                    self.message_totle.emit(len(strings))
                    for i, key in enumerate(strings):
                        if (i + 1) % max(1, len(strings) // 20) == 0 or i == len(strings) - 1:
                            self.message_log.emit(i + 1)  # 批量更新进度条

                        for known_message in stringslist:
                            # 尝试提取的字符串作为密钥，使用已知的消息进行 HMAC 并与目标 HMAC 值比较
                            computed_hmac = self.compute_hmac(known_message, key,
                                                              algo_input)  # 消息是 known_message，密钥是 decoded_str
                            if computed_hmac == target_str:
                                self.send(f"找到匹配的密钥：{key}")
                                self.send(f"找到匹配的明文：{known_message}")
                                return True
                else:
                    known_messagelist = []
                    for mm in stringslist:
                        if self.text_know in mm:
                            known_messagelist.append(mm)

                    self.message_totle.emit(len(strings))
                    for i, key in enumerate(strings):

                        if (i + 1) % max(1, len(strings) // 20) == 0 or i == len(strings) - 1:
                            self.message_log.emit(i + 1)  # 批量更新进度条

                        for known_messagelistss in known_messagelist:
                            computed_hmac = self.compute_hmac(known_messagelistss, key,
                                                              algo_input)  # 消息是 known_message，密钥是 decoded_str
                            if computed_hmac == target_str:
                                self.send(f"找到匹配的密钥：{key}")
                                self.send(f"找到匹配的明文：{known_messagelistss}")
                                return True
        return None

    def send(self, message):
        self.message_changed.emit(f"{message}")



    def run(self):


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

        result = self.find_matching_plaintext(dump_file, target_hash, algo_input, use_hmac)

        if not result:

            self.send(f"*******未找到算法{self.hash_name}匹配的明文或密钥*******\n")

        else:
            self.send(f"*******算法{self.hash_name}匹配成功*******\n")

        self.message_end.emit()
