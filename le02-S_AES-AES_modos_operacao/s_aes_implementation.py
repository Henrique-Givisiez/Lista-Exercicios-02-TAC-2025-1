class SAES:
    def __init__(self, key):
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

    def pega_round_keys(self):
        return self.__round_keys 

    def cria_state_array(self, bloco: list[int]) -> list[list[int]]:
        b0 = (bloco >> 12) & 0xF
        b1 = (bloco >> 8) & 0xF
        b2 = (bloco >> 4) & 0xF
        b3 = bloco & 0xF
        return [
                [b0, b2], 
                [b1, b3]
               ]

    def cria_blocos(self, texto: str) -> list[int]:
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

    def execucao(self, plaintext: str):
        blocos = self.cria_blocos(plaintext)
        for b in blocos:
            state_array = self.cria_state_array(b)
            print(state_array)
        return
    

def main():
    t = SAES(0xcafe)
    t.execucao("Hi")
    return 0

if __name__ == "__main__":
    main()