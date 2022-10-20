# Tiny-Encryption-Algorithm

Tiny Encryption Algorithm (TEA) is a block cipher notable for its simplicity of description and implementation, typically a few lines of code. It was designed by David Wheeler and Roger Needham of the Cambridge Computer Laboratory; it was first presented at the Fast Software Encryption workshop in Leuven in 1994, and first published in the proceedings of that workshop.
(Wikipedia [Tiny Encryption Algorithm](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm))

<figure>
<img src="https://upload.wikimedia.org/wikipedia/commons/a/a1/TEA_InfoBox_Diagram.png" alt="Two Feistel rounds (one cycle) of TEA">
<figcaption align="center">Two Feistel rounds (one cycle) of TEA</figcaption>
</figure>

## Description

`tea.py` demonstrates encryption and decryption processes of a block. The algorithm was implemented based on the pseudo-code for TEA encryption and decryption depicted in **Stamp, Mark.** "Symmetric Key Crypto." _Information Security: Principles and Practice_, Wiley, 2011, pp. 70–72.

`tea_ecb.py` reads text from `msg.txt`, encrypts the text using ECB block cipher mode, and saves the hexadecimal results to a text file named `msg.txt.ecb.enc`. It also reads the encrypted text file, decrypts the result, and saves the result to `msg.txt.ecb.dec`.

<figure>
<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/d/d6/ECB_encryption.svg/601px-ECB_encryption.svg.png" alt="Electronic Codebook (ECB) mode encryption">
</figure>
<figure>
<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png" alt="Electronic Codebook (ECB) mode decryption">
</figure>

`tea_cbc.py` reads text from `msg.txt`, encrypts the text using CBC block cipher mode, and saves the hexadecimal results to a text file named `msg.txt.cbc.enc`. It also reads the encrypted text file, decrypts the result, and saves the result to `msg.txt.cbc.dec`.

<figure>
<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/600px-CBC_encryption.svg.png" alt="Cipher Block Chaining (CBC) mode encryption">
</figure>
<figure>
<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/600px-CBC_decryption.svg.png" alt="Cipher Block Chaining (CBC) mode decryption">
</figure>
