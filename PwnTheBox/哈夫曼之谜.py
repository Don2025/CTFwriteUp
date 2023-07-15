from ast import main
from typing import Dict


class Node:
    def __init__(self, value, weight, lchild=None, rchild=None):
        self.value = value
        self.weight = weight
        self.lchild = lchild
        self.rchild = rchild

class HuffmanTree():
    def __init__(sefreq_dict: Dict[bytes, int]) -> Dict[bytes, str]:
        ''''
        根据词频字典构造哈夫曼编码 返回对应的编码字典
        '''
        def dfs(cur: Node, huffman_code: str, huffman_dic: Dict[bytes, str]):
            if cur is None:
                return
            else:
                if cur.lchild is None and cur.rchild is None:
                    huffman_dic[cur.value] = huffman_code
                dfs(cur.lchild, huffman_code + '0', huffman_dic)
                dfs(cur.rchild, huffman_code + '1', huffman_dic)

        if len(freq_dict) == 0:
            return {}
        elif len(freq_dict) == 1:
            return {freq_dict.keys()[0]: '0'}
        # 初始化森林
        node_lst = [Node(value, weight) for value, weight in freq_dict.items()]
        node_lst.sort(key=lambda x: x.weight, reverse=True)
        # 构建哈夫曼树
        while len(node_lst) > 1:
            # 取出权重最小的两个节点进行合并
            left = node_lst.pop()
            right = node_lst.pop()
            node_lst.append(Node(None, left.weight + right.weight, left, right))
            # 按照权重排序
            index = len(node_lst) - 1
            while index and node_lst[index].weight < node_lst[index - 1].weight:
                node_lst[index], node_lst[index - 1] = node_lst[index - 1], node_lst[index]
                index -= 1
        # 构建哈夫曼编码
        huffman_dic = {key: '' for key in freq_dict.keys()}
        dfs(node_lst[0], '', huffman_dic)
        return huffman_dic

    def wordfreq(bytes_str: bytes):
        '''
        统计目标文本的字符频数 返回词频字典
        '''
        freq_dict = [0 for _ in range(256)]
        for item in bytes_str:
            freq_dict[item] += 1
        return {bytes([i]): freq_dict[i] for i in range(256) if freq_dict[i] != 0}

    def decode(huffman_code: str, huffman_dic: Dict[bytes, str], padding: int, visualize: bool = False) -> bytes:
        '''
        huffman_code: 带解码的哈夫曼编码
        huffman_dic: 哈夫曼编码词频字典
        padding: 末端填充的字节数
        根据哈夫曼编码字典和哈夫曼编码进行解码
        '''
        if not huffman_code:
            return b''
        elif len(huffman_code) == 1:
            huffman_dic[b'OVO'] = 'OVO'            
        # 初始化森林, 短码在前，长码在后, 长度相等的码字典序小的在前
        node_lst = [Node(value, weight, None, None) for value, weight in huffman_dic.items()]
        node_lst.sort(key=lambda _item: (len(_item.weight), _item.weight), reverse=False)
        # 构建Huffman树
        while len(node_lst) > 1:
            # 合并最后两棵树
            node_2 = node_lst.pop()
            node_1 = node_lst.pop()
            node_add = Node(None, node_1.weight[:-1:], node_1, node_2)
            node_lst.append(node_add)
            # 调整森林
            node_lst.sort(key=lambda _item: (len(_item.weight), _item.weight), reverse=False)
        # 解密文本
        read_buffer, buffer_size = [], 0
        # 生成字符->二进制列表的映射
        dic = [list(map(int, bin(item)[2::].rjust(8, '0'))) for item in range(256)]
        # 将huffman_code转化为二进制列表
        for item in huffman_code:
            read_buffer.extend(dic[item])
            buffer_size = buffer_size + 8
        read_buffer = read_buffer[0: buffer_size - padding:]
        buffer_size = buffer_size - padding
        write_buffer = bytearray([])
        current = node_lst[0]
        for pos in tqdm(range(0, buffer_size, 8), unit='byte', disable=not visualize):
            for item in read_buffer[pos:pos + 8]:
                # 根据二进制数移动current
                if item:
                    current = current.rchild
                else:
                    current = current.lchild
                # 到达叶结点，打印字符并重置current
                if current.lchild is None and current.rchild is None:
                    write_buffer.extend(current.value)
                    current = node_lst[0]

        return bytes(write_buffer)

if __name__ == '__main__':
    freq_dict = [('a', 4), ('d',9), ('g', 1), ('f', 5), ('l', 1), ('0', 7), ('5', 9), ('{', 1), ('}', 1)]
    tree = HuffmanTree(freq_dict)
    tree.decode('11000111000001010010010101100110110101111101110101011110111111100001000110010110101111001101110001000110')