数据转换工具

一个简洁的命令行工具，用于将Base64、URL编码或ASCII数值数据转换为二进制文件。
功能
支持三种输入格式：
Base64编码
URL编码
ASCII数值（二进制、八进制、十进制、十六进制）
自动检测输入格式
二进制位顺序反转选项
转换结果预览
使用方法

bash
python3 converter.py [输出文件前缀] < input.txt
参数说明
[输出文件前缀]：可选参数，指定输出文件名前缀（默认为"converted_data"）
交互流程
1. 选择输入数据格式（1-3）
2. 对于ASCII数值格式，确认源数据进制
3. 对于ASCII转二进制，选择是否反转位顺序
4. 查看转换结果和保存路径
示例
Base64转换
bash
echo "SGVsbG8gV29ybGQh" python3 converter.py hello
十六进制数据转换
bash
echo "48656c6c6f20576f726c6421" python3 converter.py hello
二进制数据转换（带位反转）
bash
echo "01001000 01100101 01101100 01101100 01101111" python3 converter.py hello
选择是否反转位顺序时输入 y
输出说明

转换完成后，脚本会显示：
转换描述
保存路径
文件大小
数据预览（十六进制和ASCII表示）

输出文件格式为.bin，可使用任何二进制分析工具进一步处理。
依赖
Python 3.x
标准库（无需额外安装包）
注意事项
对于ASCII数值输入，脚本会尝试自动检测进制格式
二进制位反转功能只适用于每个字节内的位顺序反转
处理大型文件时，建议先截取关键部分再进行转换分析
