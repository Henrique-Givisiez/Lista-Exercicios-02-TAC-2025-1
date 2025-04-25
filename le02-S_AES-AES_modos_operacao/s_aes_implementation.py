import base64

class SAES:
    def __init__(self, chave: int):
        """
        Inicializa o objeto SAES com a chave fornecida e configura os componentes necessários.
        
        Args:
            chave: Chave de 16 bits para fazer a criptografia
        """
        self.chave = chave
        self.__sbox = {
            0x0: 0x9, 0x1: 0x4, 0x2: 0xA, 0x3: 0xB,
            0x4: 0xD, 0x5: 0x1, 0x6: 0x8, 0x7: 0x5,
            0x8: 0x6, 0x9: 0x2, 0xA: 0x0, 0xB: 0x3,
            0xC: 0xC, 0xD: 0xE, 0xE: 0xF, 0xF: 0x7
        }
        self.__subchaves = [0] * 6  # Armazena as subchaves k0 a k5
        self.__rcon = [0x80, 0x30]  # Constantes de rodada para expansão da chave

    def __g(self, palavra: int, rodada: int) -> int:
        """
        Realiza a transformação da word durante a key expansion (RotWord + SubNib + Rcon).
        
        Args:
            palavra: Palavra de 8 bits a ser transformada
            rodada: Número da rodada atual
            
        Returns:
            int: Palavra transformada após as operações
        """
        palavra = ((palavra << 4) | (palavra >> 4)) & 0xFF  # Rotaciona nibbles
        palavra = self.__substitui_nibbles(palavra)         # Substitui usando S-box
        return palavra ^ self.__rcon[rodada]                # Aplica XOR com Rcon

    def __substitui_nibbles(self, byte: int) -> int:
        """
        Realiza a substituição de nibbles usando a S-box.
        
        Args:
            byte: Byte de 8 bits para substituição
            
        Returns:
            int: Byte resultante após substituição dos nibbles
        """
        msb = self.__sbox[(byte >> 4) & 0xF]  # Parte mais significativa
        lsb = self.__sbox[byte & 0xF]         # Parte menos significativa
        return (msb << 4) | lsb

    def key_expansion(self) -> None:
        """
        Gera as round keys subsequentes.
        
        Detalhes:
            - Deriva 6 words de 8 bits (3 round keys) da chave principal
            - Utiliza a função g para as palavras em posições pares
        """
        self.__subchaves[0] = self.chave >> 8
        self.__subchaves[1] = self.chave & 0xFF
        for i in range(2, 6):
            if i % 2 == 0:
                self.__subchaves[i] = self.__subchaves[i-2] ^ self.__g(self.__subchaves[i-1], i//2 - 1)
            else:
                self.__subchaves[i] = self.__subchaves[i-1] ^ self.__subchaves[i-2]

    def __cria_blocos(self, texto: str) -> list[int]:
        """
        Divide o texto em blocos de 16 bits com padding se necessário.
        
        Args:
            texto: Texto nao crifrado a ser processado
            
        Returns:
            list[int]: Lista de blocos de 16 bits
        """
        dados = list(texto.encode("utf-8"))
        if len(dados) % 2 != 0:
            dados.append(0x00)
        blocos = [(dados[i] << 8) | dados[i+1] for i in range(0, len(dados), 2)]
        return blocos

    def __cria_matriz_estado(self, bloco: int) -> list[list[int]]:
        """
        Converte um bloco de 16 bits em uma matriz de estado 2x2 de nibbles.
        
        Args:
            bloco: Bloco de 16 bits
            
        Returns:
            list[list[int]]: Matriz 2x2 de nibbles
        """
        nibble0 = (bloco >> 12) & 0xF  # Primeiro nibble
        nibble1 = (bloco >> 8) & 0xF   # Segundo nibble
        nibble2 = (bloco >> 4) & 0xF   # Terceiro nibble
        nibble3 = bloco & 0xF          # Quarto nibble
        
        return [[nibble0, nibble2], 
                [nibble1, nibble3]]

    def __add_round_key(self, matriz: list[list[int]], rodada: int) -> list[list[int]]:
        """
        Aplica a operação AddRoundKey usando a chave da rodada especificada.
        
        Args:
            matriz: Matriz de estado atual
            rodada: Número da rodada (0, 1 ou 2)
            
        Returns:
            list[list[int]]: Novo estado após usar a chave
        """
        # Seleciona chave da rodada
        if rodada == 0:
            k = self.__subchaves[0:2]
        elif rodada == 1:
            k = self.__subchaves[2:4]
        else:
            k = self.__subchaves[4:6]

        # Quebra as subchaves em nibbles
        k0 = [(k[0] >> 4) & 0xF, k[0] & 0xF]
        k1 = [(k[1] >> 4) & 0xF, k[1] & 0xF]

        return [
            [matriz[0][0] ^ k0[0], matriz[0][1] ^ k1[0]],
            [matriz[1][0] ^ k0[1], matriz[1][1] ^ k1[1]]
        ]

    def __shift_rows(self, matriz: list[list[int]]) -> list[list[int]]:
        """
        Rotaciona a segunda linha da matriz de estado.
        
        Args:
            matriz: Matriz de estado atual
            
        Returns:
            list[list[int]]: Novo estado após deslocamento
        """
        matriz[1][0], matriz[1][1] = matriz[1][1], matriz[1][0]
        return matriz

    def __mix_columns(self, matriz: list[list[int]]) -> list[list[int]]:
        """
        Realiza a operação MixColumns utilizando multiplicação em campo finito GF(2^4).
                
        Args:
            matriz: Matriz de estado atual
            
        Returns:
            list[list[int]]: Novo estado após 'misturar' colunas
        """
        resultado = [[0, 0], [0, 0]]
        for coluna in range(2):
            a = matriz[0][coluna]
            b = matriz[1][coluna]
            # Multiplicação GF(2^4)
            resultado[0][coluna] = self.__gf_mul(1, a) ^ self.__gf_mul(4, b)
            resultado[1][coluna] = self.__gf_mul(4, a) ^ self.__gf_mul(1, b)
        return resultado

    def __gf_mul(self, a: int, b: int) -> int:
        """
        Realiza multiplicação no campo de Galois GF(2^4) com polinômio irreducível x^4 + x + 1.
        
        Args:
            a: Primeiro operando (4 bits)
            b: Segundo operando (4 bits)
            
        Returns:
            int: Resultado da multiplicação (também em 4 bits)
        """
        resultado = 0
        for _ in range(4):
            if b & 1:
                resultado ^= a
            carry = a & 0x8  # Verifica bit x³
            a <<= 1
            if carry:
                a ^= 0x13  # Redução usando x⁴ + x + 1 (0b10011
            b >>= 1
        return resultado & 0xF  # Garante 4 bits

    def imprime(self, blocos_cifrados: list[int]) -> None:
        """
        Exibe os blocos cifrados em hexadecimal e Base64.

        Args:
            blocos_cifrados (list[int]): Lista de blocos cifrados (16 bits cada)
        """
        dados = bytearray()
        for bloco in blocos_cifrados:
            dados.append((bloco >> 8) & 0xFF)
            dados.append(bloco & 0xFF)

        print("Hexadecimal:", dados.hex())
        print("Base64:", base64.b64encode(dados).decode())

    def criptografa(self, plaintext: str) -> list[int]:
        """
        Realiza a criptografia do texto utilizando o S-AES.
        
        Args:
            plaintext: Texto a ser cifrado
            
        Returns:
            list[int]: Lista de blocos cifrados
        """
        blocos = self.__cria_blocos(plaintext)
        blocos_cifrados = []

        for bloco in blocos:
            estado = self.__cria_matriz_estado(bloco)
            estado = self.__add_round_key(estado, 0)

            for rodada in range(1, 3):
                # Aplica substituição de nibbles por coluna
                col1 = self.__substitui_nibbles((estado[0][0] << 4) | estado[1][0])
                col2 = self.__substitui_nibbles((estado[0][1] << 4) | estado[1][1])
                estado = [
                    [(col1 >> 4) & 0xF, (col2 >> 4) & 0xF],
                    [col1 & 0xF, col2 & 0xF]
                ]

                estado = self.__shift_rows(estado)

                if rodada != 2:
                    estado = self.__mix_columns(estado)

                estado = self.__add_round_key(estado, rodada)

            # Reconstrói bloco de 16 bits
            bloco_cifrado = (estado[0][0] << 12) | (estado[1][0] << 8) | (estado[0][1] << 4) | estado[1][1]
            blocos_cifrados.append(bloco_cifrado)

        return blocos_cifrados


def main():
    chave = 0xCAFE
    s_aes = SAES(chave=chave)
    s_aes.key_expansion()

    texto = input("Digite o texto para criptografar\n").strip()
    blocos_cifrados = s_aes.criptografa(texto)
    
    s_aes.imprime(blocos_cifrados)


if __name__ == "__main__":
    main()
