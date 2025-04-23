import base64
class SAES:
    def __init__(self, key: int):
        self.key = key
        self.__sbox = {
            0x0: 0x9, 0x1: 0x4, 0x2: 0xA, 0x3: 0xB,
            0x4: 0xD, 0x5: 0x1, 0x6: 0x8, 0x7: 0x5,
            0x8: 0x6, 0x9: 0x2, 0xA: 0x0, 0xB: 0x3,
            0xC: 0xC, 0xD: 0xE, 0xE: 0xF, 0xF: 0x7
        }
        self.__round_keys = [0, 0, 0, 0, 0, 0]
        self.__rcon = [0x80, 0x30]

    def __g(self, word: int, round: int) -> int:
        """
        Realiza a transformação da palavra de entrada (byte) durante o processo de geração de chaves no algoritmo S-AES.
        Args:
            word (int): Byte de entrada representado como um inteiro de 8 bits.
            round (int): Número da rodada atual, usado para selecionar a constante de rodada (Rcon).
        Returns:
            int: Resultado da transformação após aplicar RotWord, SubNib e a operação XOR com a constante de rodada.
        """
        # RotWord: realiza uma rotação nos nibbles (4 bits)
        # Troca os dois nibbles do byte. Exemplo: 0xFE -> 0xEF
        word = ((word << 4) | (word >> 4)) & 0xFF

        # SubNib: aplica a substituição dos nibbles usando a S-box
        # Exemplo: 0xEF -> 0xF7
        word = self.__sub_nib(word)

        # XOR com Rcon: realiza uma operação XOR entre o resultado e o valor da constante de rodada (Rcon)
        return word ^ self.__rcon[round]
    
    def __sub_nib(self, byte: int) -> int:
        """
        Substitui os nibbles (segmentos de 4 bits) de um byte dado usando a S-box.

        Este método recebe um byte de 8 bits, divide-o em seu nibble mais significativo (MSB)
        e nibble menos significativo (LSB), substitui cada nibble usando a S-box, 
        e então combina os nibbles substituídos de volta em um único byte.

        Argumentos:
            byte (int): Um inteiro de 8 bits (0-255) representando o byte a ser substituído.

        Retorna:
            int: Um inteiro de 8 bits (0-255) representando o byte substituído.

        Nota:
            - A S-box é uma tabela de substituição predefinida armazenada em `self.__sbox`.
            - O MSB é extraído deslocando o byte 4 bits para a direita e mascarando 
            os 4 bits inferiores.
            - O LSB é extraído mascarando os 4 bits inferiores do byte.
            - O MSB e o LSB substituídos são combinados deslocando o MSB substituído 
            4 bits para a esquerda e realizando um OR bit a bit com o LSB substituído.
        """
        msb = self.__sbox[(byte >> 4) & 0xF]
        lsb = self.__sbox[byte & 0xF]
        return (msb << 4) | lsb
    
    def key_expansion(self) -> list[int]:
        """
        Realiza a expansão da chave para o algoritmo de criptografia.

        Este método gera uma lista de palavras (subchaves) a partir da chave principal,
        que serão utilizadas em diferentes rodadas do S-AES.

        Detalhes:
            - As duas primeiras palavras são derivadas diretamente da chave principal.
            - As palavras subsequentes são geradas utilizando operações XOR e uma função
              de transformação interna (`__g`), dependendo do índice da palavra.
            - A função `__g` é aplicada em palavras específicas para introduzir não-linearidade
              e complexidade na expansão da chave.
        """
        self.__round_keys[0] = self.key >> 8
        self.__round_keys[1] = self.key & 0xFF
        for i in range(2, 6):
            if i % 2:
                self.__round_keys[i] = self.__round_keys[i-1] ^ self.__round_keys[i-2]
            else:
                self.__round_keys[i] = self.__round_keys[i-2] ^ self.__g(self.__round_keys[i-1], i//2 - 1)
        return

    def __cria_blocos(self, texto: str) -> list[int]:
        # Codifica texto em bytes
        dados = list(texto.encode("utf-8"))

        # Se quantidade de bytes for ímpar, adiciona padding com 0
        if len(dados) % 2 != 0:
            dados.append(0x00)

        # Agrupa em blocos de 2 bytes (16 bits)
        blocos = []
        for i in range(0, len(dados), 2):
            bloco = (dados[i] << 8) | dados[i+1]
            blocos.append(bloco)

        return blocos

    def __cria_state_array(self, bloco: list[int]) -> list[list[int]]:
        b0 = (bloco >> 12) & 0xF
        b1 = (bloco >> 8) & 0xF
        b2 = (bloco >> 4) & 0xF
        b3 = bloco & 0xF
        return [[b0, b2], 
                [b1, b3]]

    def __add_round_key(self, state_arr: list[list[int]], round: int) -> list[list[int]]:
        b0 = state_arr[0][0]
        b1 = state_arr[1][0]
        b2 = state_arr[0][1]
        b3 = state_arr[1][1]
        if round == 0:
            words = self.__round_keys[0:2]
        elif round == 1:
            words = self.__round_keys[2:4]
        else:
            words = self.__round_keys[4:]
        b0 = b0 ^ ((words[0] >> 4) & 0xF)
        b1 = b1 ^ (words[0] & 0xF)
        b2 = b2 ^ ((words[1] >> 4) & 0xF)
        b3 = b3 ^ (words[1] & 0xF)
        
        return [[b0,b2],
                [b1,b3]]
    
    def __shift_rows(self, state_arr: list[list[int]]) -> list[list[int]]:
        state_arr[1][0], state_arr[1][1] = state_arr[1][1], state_arr[1][0]
        return state_arr
    
    def __mix_columns(self, state_arr: list[list[int]]) -> list[list[int]]:
        result = [[0, 0], [0, 0]]
        for col in range(2):
            a = state_arr[0][col]
            b = state_arr[1][col]
            result[0][col] = self.__gf_mul(1, a) ^ self.__gf_mul(4, b)
            result[1][col] = self.__gf_mul(4, a) ^ self.__gf_mul(1, b)
        return result
    
    def __gf_mul(self, a, b):
        p = 0
        for i in range(4):  # max 4 bits
            if b & 1:
                p ^= a
            carry = a & 0x8  # se o bit mais alto está setado (x³)
            a <<= 1
            if carry:
                a ^= 0x13  # módulo irreducível x⁴ + x + 1
            b >>= 1
        return p & 0xF  # garante que o resultado está em 4 bits

    def imprime(self, blocos_cifrados: list[int]) -> None:
        bytes_cifrados = bytearray()
        for bloco in blocos_cifrados:
            bytes_cifrados.append((bloco >> 8) & 0xFF)
            bytes_cifrados.append(bloco & 0xFF)

        print("Hexadecimal:", bytes_cifrados.hex())

        b64 = base64.b64encode(bytes_cifrados).decode()
        print("Base64:", b64)
        return
    
    def criptografa(self, plaintext: str):
        blocos = self.__cria_blocos(plaintext)
        blocos_cifrados = []
        for b in blocos:
            state_array = self.__cria_state_array(b)
            state_array = self.__add_round_key(state_array, 0)
            for i in range(1,3):
                byte1 = (state_array[0][0] << 4) | state_array[1][0]
                col1 = self.__sub_nib(byte1)
                byte2 = (state_array[0][1] << 4) | state_array[1][1]
                col2 = self.__sub_nib(byte2)
                state_array = [[(col1 >> 4) & 0xF, (col2 >> 4) & 0xF],
                               [col1 & 0xF, col2 & 0xF]]

                state_array = self.__shift_rows(state_array)

                if i != 2:
                    state_array = self.__mix_columns(state_array)

                state_array = self.__add_round_key(state_array, i)

            # Converte a matriz 2x2 de nibbles de volta para inteiro de 16 bits
            b0 = state_array[0][0]
            b1 = state_array[1][0]
            b2 = state_array[0][1]
            b3 = state_array[1][1]
            bloco_final = (b0 << 12) | (b1 << 8) | (b2 << 4) | b3
            blocos_cifrados.append(bloco_final)

        return blocos_cifrados

def main():
    key = 0xCAFE
    s_aes = SAES(key=key)
    s_aes.key_expansion()
    
    plaintext = "string curta"
    mensagem_cifrada = s_aes.criptografa(plaintext)

    s_aes.imprime(mensagem_cifrada)
    return

if __name__ == "__main__":
    main()