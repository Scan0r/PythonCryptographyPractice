# PythonCryptographyPractice

OSCP Project: Python cryptography practice about symmetric ciphering and hash functions with the "cryptography" library.

## Dependencies

This script use the python cryptographic library called "cryptography". This library can be installed in the following way:

```bash
$ pip3 install cryptography
```

More details about its installation can be found at this link: https://cryptography.io/en/latest/installation/

## Practice Tasks

### Task 1

This task allows you to practice how to encrypt a text with the AES algorithm, the current symmetric encryption standard. 

a) The exercise consists of encrypting the message "a secret message" with the key '123456789012345678901234567890123456789012'. 

Use the CBC encryption mode. Decrypt the cryptogram and check that you get the original text.

b) In this section we are going to see the difference between the different encryption modes. To do this repeat the previous exercise, using the OFB, CFB, ECB encryption modes. Compare the cryptogram obtained in each of the cases.

If you run the program several times, is the result of the ciphertexts always the same or does it vary? What is the reason for this phenomenon?

### Task 2

In this exercise we are going to program a function to calculate the hash of a file. This can be used to check the integrity of a downloaded file.

Using the MD5 hash function of the "cryptography" library, program a function that calculates the MD5 hash of the files "WinMD5.exe" and "WinMD5_2.exe".

What are the hashes of each of the files? Considering that the hash of the original file is 944a1e869969dd8a4b64ca5e6ebc209a, which of the files is correct?
