# Tiny-Encryption-Algorithm

Tiny Encryption Algorithm (TEA) is a block cipher notable for its simplicity of description and implementation, typically a few lines of code. It was designed by David Wheeler and Roger Needham of the Cambridge Computer Laboratory; it was first presented at the Fast Software Encryption workshop in Leuven in 1994, and first published in the proceedings of that workshop.
(Wikipedia [Tiny Encryption Algorithm](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm))

![Two Feistel rounds (one cycle) of TEA](https://upload.wikimedia.org/wikipedia/commons/a/a1/TEA_InfoBox_Diagram.png)

## Description

`tea.py` demonstrates encryption and decryption processes of a block

`tea_ecb.py` reads text from `msg.txt`, encrypts the text using ECB block cipher mode, and saves the hexadecimal results to a text file named `msg.txt.ecb.enc`. It also reads the encrypted text file, decrypts the result, and saves the result to `msg.txt.ecb.dec`.

![Electronic Codebook (ECB) mode encryption](https://upload.wikimedia.org/wikipedia/commons/thumb/d/d6/ECB_encryption.svg/601px-ECB_encryption.svg.png)
![Electronic Codebook (ECB) mode decryption](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

`tea_cbc.py` reads text from `msg.txt`, encrypts the text using CBC block cipher mode, and saves the hexadecimal results to a text file named `msg.txt.cbc.enc`. It also reads the encrypted text file, decrypts the result, and saves the result to `msg.txt.cbc.dec`.

![Cipher Block Chaining (CBC) mode encryption](https://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/600px-CBC_encryption.svg.png)
![Cipher Block Chaining (CBC) mode decryption](https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/600px-CBC_decryption.svg.png)
