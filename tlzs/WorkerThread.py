import base64
import binascii
import hashlib
import hmac
import io
import json
import re
from Crypto.Cipher import DES3
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
from PyQt5.QtCore import QThread, pyqtSignal
from Crypto.Cipher import AES

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

    def is_valid_json(self, json_string) :

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
                print('hex')
                return binascii.unhexlify(s)

            except (binascii.Error, ValueError):
                pass

        # 尝试匹配 Base64 格式（标准的 Base64 字符串只包含A-Z, a-z, 0-9, +, /）
        try:
            base64_bytes = base64.b64decode(s, validate=True)
            if base64.b64encode(base64_bytes).decode('utf-8') == s:
                print('base64')
                return base64_bytes
        except (binascii.Error, ValueError):
            pass

        # 默认将其视为明文并转为二进制
        print('utf-8')
        return s.encode('utf-8')

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

    def find_matching_plaintext(self, dump_file, target_str, algo_input, use_hmac):

        """在内存转储文件中搜索匹配的明文或密钥"""

        target_str = self.detect_format_and_convert_to_binary(target_str)

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
                                     b'0000000000000000')

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
                                     b'00000000')
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

            if not use_hmac:

                if self.text_know:
                    self.message_totle.emit(len(strings))
                    for i, decoded_str in enumerate(strings):

                        try:
                            decoded_str = decoded_str.decode('utf-8')
                            if self.text_know_type == 'json格式':
                                if not self.is_valid_json(decoded_str.decode()):
                                    continue
                            if self.text_know not in decoded_str:
                                continue
                        except:
                            continue

                        if (i + 1) % max(1, len(strings) // 100) == 0 or i == len(strings) - 1:
                            self.message_log.emit(i + 1)  # 批量更新进度条

                        if self.compute_hash(decoded_str, algo_input) == target_str:
                            self.send(f"找到匹配的明文：{decoded_str}")
                            return True
                else:
                    self.message_totle.emit(len(strings))
                    for i, decoded_str in enumerate(strings):

                        try:
                            decoded_str = decoded_str.decode('utf-8')
                            if self.text_know_type == 'json格式':
                                if not self.is_valid_json(decoded_str.decode()):
                                    continue
                        except:
                            continue

                        if (i + 1) % max(1, len(strings) // 100) == 0 or i == len(strings) - 1:
                            self.message_log.emit(i + 1)  # 批量更新进度条

                        if self.compute_hash(decoded_str, algo_input) == target_str:
                            self.send(f"找到匹配的明文：{decoded_str}")
                            return True
            else:
                if not self.text_know:
                    self.message_totle.emit(len(strings))
                    for i, key in enumerate(strings):

                        if (i + 1) % max(1, len(strings) // 100) == 0 or i == len(strings) - 1:
                            self.message_log.emit(i + 1)  # 批量更新进度条

                        for known_message in strings:

                            try:
                                known_message = known_message.decode('utf-8')
                                if self.text_know_type == 'json格式':
                                    if not self.is_valid_json(known_message.decode()):
                                        continue
                            except:
                                continue

                            # 尝试提取的字符串作为密钥，使用已知的消息进行 HMAC 并与目标 HMAC 值比较
                            computed_hmac = self.compute_hmac(known_message, key,
                                                              algo_input)  # 消息是 known_message，密钥是 decoded_str
                            if computed_hmac == target_str:
                                self.send(f"找到匹配的密钥：{key}")
                                self.send(f"找到匹配的明文：{known_message}")
                                return True
                else:

                    self.message_totle.emit(len(strings))
                    for i, key in enumerate(strings):

                        if (i + 1) % max(1, len(strings) // 100) == 0 or i == len(strings) - 1:
                            self.message_log.emit(i + 1)  # 批量更新进度条

                        for known_messagelistss in stringslist:

                            try:
                                known_messagelistss = known_messagelistss.decode('utf-8')
                                if self.text_know_type == 'json格式':
                                    if not self.is_valid_json(known_messagelistss.decode()):
                                        continue
                                if self.text_know not in known_messagelistss:
                                    continue
                            except:
                                continue

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
        print(algo_input)

        # 检查是否使用 HMAC
        use_hmac = algo_input.startswith("hmac")
        if use_hmac:
            algo_input = algo_input[4:]  # 去掉 "hmac" 前缀
        else:
            algo_input = algo_input

        result = self.find_matching_plaintext(dump_file, target_hash, algo_input, use_hmac)

        if not result:

            self.send("未找到匹配的明文或密钥。")

        else:
            self.send("匹配成功")

        self.message_end.emit()
