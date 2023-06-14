from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss
import os

directory = "sciezka"

def GetFileDirectory(fileName):
    return directory + "\\" + fileName

def ShowFiles():
    files = os.listdir(directory)
    for file in files:
        print(file) 

while(1):    
    option = input("1. podpisz plik, 2. sprawdź plik, Wybrana opcja: ")

    if (option == '1'):
        ShowFiles()
        
        privateKey = RSA.generate(1024, Random.new().read)
        publicKey = privateKey.publickey()

        file = open(GetFileDirectory(input("Podaj plik do podpisania: ")), "rb").read()
        hash = SHA256.new()
        hash.update(file)
        signature = pss.new(privateKey).sign(hash)
        
        saveKey = open(GetFileDirectory("klucz.txt"), 'wb')
        saveKey.write(publicKey.export_key('PEM'))
        saveKey.close()

        saveSign = open(GetFileDirectory("podpis.txt"), "wb")
        saveSign.write(signature)
        saveSign.close()
    
    if (option == '2'):
        ShowFiles()

        fileToVerify = open(GetFileDirectory(input("Podaj plik do sprawdzenia: ")), "rb").read()
        fileSign = open(GetFileDirectory(input("Podaj podpisany plik: ")), "rb").read()

        hash = SHA256.new()
        hash.update(fileToVerify)
        
        try:
            savedKey = open(GetFileDirectory("klucz.txt"), 'rb').read()
            savedKey = RSA.import_key(savedKey)
        except(ValueError, TypeError):
            print("Klucz jest uszkodzony")
            continue

        verifier = pss.new(savedKey)

        try:
            verifier.verify(hash, fileSign)
            print("Podpis sie zgadza")
        except(ValueError, TypeError):
            print("Podpis sie nie zgadza, zly plik")