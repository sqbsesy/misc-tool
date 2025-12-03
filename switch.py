#!/usr/bin/env python3
import base64
import binascii
import sys
import os
import urllib.parse
import re
from typing import Tuple, List

def reverse_bits_in_bytes(data: bytes) -> bytes:
    """反转每个字节中的位顺序"""
    result = bytearray()
    for byte in data:
        reversed_byte = 0
        for i in range(8):
            if byte & (1 << i):
                reversed_byte |= (1 << (7 - i))
        result.append(reversed_byte)
    return bytes(result)

def main():
    base_output_path = sys.argv[1] if len(sys.argv) > 1 else "converted_data"
    
    # 获取输入格式选择
    print("\n选择输入数据格式:")
    print("1. Base64 编码")
    print("2. URL 编码")
    print("3. ASCII 数值")
    
    while True:
        choice = input("\n请选择 (1-3) [默认1]: ").strip() or "1"
        if choice in ["1", "2", "3"]:
            input_format = ["base64", "url", "ascii"][int(choice)-1]
            break
        print("无效选择! 请输入1-3之间的数字")
    
    # 读取输入数据
    print(f"\n输入{input_format}数据 (Ctrl+D结束):")
    if input_format == "ascii":
        raw_data = sys.stdin.read().encode('utf-8')
    else:
        raw_data = sys.stdin.buffer.read()
    
    try:
        # 处理输入数据
        if input_format == "base64":
            lines = raw_data.decode('utf-8', errors='ignore').strip().splitlines()
            if len(lines) > 1:
                binary, desc = process_multiline_base64(lines)
            else:
                binary, desc = process_base64_input(raw_data)
            output_path = f"{base_output_path}_b64.bin"
            
        elif input_format == "url":
            binary, desc = process_url_input(raw_data)
            output_path = f"{base_output_path}_url.bin"
            
        else:  # ascii
            binary, desc = process_ascii_input(raw_data)
            output_path = f"{base_output_path}_ascii.bin"
        
        # 保存文件
        with open(output_path, "wb") as f:
            f.write(binary)
        
        # 显示结果
        print(f"\n转换成功: {desc}")
        print(f"已保存至: {os.path.abspath(output_path)}")
        print(f"文件大小: {len(binary)} 字节")
        
        # 简要预览
        preview_size = min(16, len(binary))
        if preview_size > 0:
            hex_preview = ' '.join(f'{b:02X}' for b in binary[:preview_size])
            ascii_preview = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in binary[:preview_size])
            print(f"预览: {hex_preview}")
            print(f"ASCII: {ascii_preview}")
            
    except Exception as e:
        print(f"\n错误: {str(e)}")
        sys.exit(1)

def process_multiline_base64(lines: List[str]) -> Tuple[bytes, str]:
    """处理多行Base64数据"""
    binary_data = b''
    
    for i, line in enumerate(lines):
        if not line.strip():
            continue
            
        clean_line = line.strip()
        
        # 补全等号
        missing_padding = len(clean_line) % 4
        if missing_padding:
            clean_line += '=' * (4 - missing_padding)
        
        try:
            decoded = base64.b64decode(clean_line)
            binary_data += decoded
        except binascii.Error as e:
            continue
    
    if not binary_data:
        raise ValueError("没有成功解码任何Base64行")
    
    desc = f"多行Base64: {len(binary_data)}字节"
    return binary_data, desc

def process_base64_input(raw_data: bytes) -> Tuple[bytes, str]:
    """处理单行Base64输入"""
    if not raw_data:
        raise ValueError("未检测到输入数据")
    
    clean_data = raw_data.strip()
    
    # 自动补全等号
    if len(clean_data) % 4 != 0:
        missing_padding = len(clean_data) % 4
        clean_data += b'=' * (4 - missing_padding)
    
    try:
        binary = base64.b64decode(clean_data)
    except binascii.Error:
        clean_data = re.sub(b'[^A-Za-z0-9+/=]', b'', clean_data)
        binary = base64.b64decode(clean_data)
    
    desc = f"Base64: {len(binary)}字节"
    return binary, desc

def process_url_input(raw_data: bytes) -> Tuple[bytes, str]:
    """处理URL编码输入"""
    if not raw_data:
        raise ValueError("未检测到输入数据")
    
    input_str = raw_data.decode('utf-8', errors='ignore').strip()
    
    # URL解码
    decoded_str = urllib.parse.unquote_plus(input_str)
    binary = decoded_str.encode('utf-8', errors='ignore')
    
    desc = f"URL解码: {len(binary)}字节"
    return binary, desc

def process_ascii_input(raw_data: bytes) -> Tuple[bytes, str]:
    """处理ASCII数值输入"""
    if not raw_data:
        raise ValueError("未检测到输入数据")
    
    text = raw_data.decode('utf-8', errors='ignore').strip()
    if not text:
        raise ValueError("输入为空")
    
    # 检测原始进制
    detected_base = detect_numeric_base(text)
    
    # 确认原始进制
    source_base = get_confirmed_base(detected_base)
    
    # 转换数据
    values = parse_numeric_text(text, source_base)
    byte_data = bytes(v & 0xFF for v in values)
    
    # 询问是否需要反转二进制位
    reverse_bits = input("\n是否需要反转每个字节的二进制位顺序? (y/n) [n]: ").strip().lower() == 'y'
    if reverse_bits:
        byte_data = reverse_bits_in_bytes(byte_data)
        bit_status = " (位已反转)"
    else:
        bit_status = ""
    
    desc = f"ASCII数值 ({source_base.upper()}) → 二进制{bit_status}: {len(byte_data)}字节"
    return byte_data, desc

def detect_numeric_base(text: str) -> str:
    """自动检测数值文本的进制"""
    # 检查十六进制特征
    if re.search(r'\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{2,4}\b', text):
        return 'hex'
    
    # 检查二进制特征
    if re.search(r'\b[01]{4,8}\b', text) or len(re.findall(r'[01]', text)) / max(1, len(text)) > 0.7:
        return 'bin'
    
    # 检查八进制特征
    if re.search(r'\b[0-7]{3}\b', text):
        return 'oct'
    
    return 'dec'  # 默认十进制

def get_confirmed_base(detected: str) -> str:
    """让用户确认原始进制"""
    print(f"\n检测到: {detected.upper()} 格式")
    
    options = {
        '1': 'bin',
        '2': 'oct',
        '3': 'dec',
        '4': 'hex'
    }
    
    while True:
        print("\n1. 二进制 (0/1)")
        print("2. 八进制 (0-7)")
        print("3. 十进制 (0-255)")
        print("4. 十六进制 (0-9/A-F)")
        choice = input(f"确认格式 (1-4) [默认{list(options.keys())[list(options.values()).index(detected)]}]: ").strip() or str(list(options.keys())[list(options.values()).index(detected)])
        
        if choice in options:
            return options[choice]
        print("无效选择! 请输入1-4之间的数字")

def parse_numeric_text(text: str, base: str) -> List[int]:
    """将数值文本解析为整数列表"""
    # 移除注释
    text = re.sub(r'//.*|/\*.*?\*/', '', text, flags=re.DOTALL)
    
    # 标准化分隔符
    text = re.sub(r'[\s\-_:;,]+', ' ', text).strip()
    
    # 处理十六进制前缀
    if base == 'hex':
        text = re.sub(r'0x([0-9a-fA-F]+)', r'\1', text)
    
    # 提取数值
    if base == 'bin':
        tokens = re.findall(r'[01]+', text)
    else:
        tokens = [t for t in text.split() if t]
    
    if not tokens:
        raise ValueError(f"未找到有效的{base}数值")
    
    # 转换为整数
    base_map = {'bin': 2, 'oct': 8, 'dec': 10, 'hex': 16}
    base_val = base_map[base]
    
    values = []
    for token in tokens:
        try:
            num = int(token, base_val)
            if num < 0:
                num = 256 + num  # 处理负数
            values.append(num)
        except ValueError:
            continue
    
    if not values:
        raise ValueError(f"无法解析任何{base}数值")
    
    return values

if __name__ == "__main__":
    main()
