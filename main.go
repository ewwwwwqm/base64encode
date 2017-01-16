package main

import (
    "fmt"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/hex"
    "encoding/base64"
    "io"

    "github.com/andlabs/ui"
)

func main() {
    err := ui.Main(func() {
        text := ui.NewEntry()
        keyArea := ui.NewEntry()
        encodedArea := ui.NewEntry()
        decodedArea := ui.NewEntry()
        buttonEncode := ui.NewButton("Encode")
        buttonDecode := ui.NewButton("Decode")
        upperLabel := ui.NewLabel("Enter text:")
        keyLabel := ui.NewLabel("Key (for AES enctyption, CBC):")
        encodeLabel := ui.NewLabel("Encode:")
        decodeLabel := ui.NewLabel("Decode:")
        box := ui.NewVerticalBox()
        box.Append(upperLabel, false)
        box.Append(text, false)
        box.Append(keyLabel, false)
        box.Append(keyArea, false)
        box.Append(encodeLabel, false)
        box.Append(encodedArea, false)
        box.Append(decodeLabel, false)
        box.Append(decodedArea, false)
        box.Append(buttonEncode, false)
        box.Append(buttonDecode, false)
        window := ui.NewWindow("Base64 encode/decode", 350, 120, false)
        window.SetChild(box)
        buttonEncode.OnClicked(func(*ui.Button) {
            keyEnc := string(keyArea.Text())
            if len(keyEnc) == 0 {
                encodedArea.SetText(base64.StdEncoding.EncodeToString([]byte(text.Text())))
            } else {
                key := []byte(keyEnc)
                plaintext := []byte(text.Text())

                if len(plaintext)%aes.BlockSize != 0 {
                    encodedArea.SetText("plaintext is not a multiple of the block size")
                    return
                }

                block, err := aes.NewCipher(key)
                if err != nil {
                    encodedArea.SetText(fmt.Sprintf("%v", err))
                    return
                }

                ciphertext := make([]byte, aes.BlockSize+len(plaintext))
                iv := ciphertext[:aes.BlockSize]
                if _, err := io.ReadFull(rand.Reader, iv); err != nil {
                    encodedArea.SetText(fmt.Sprintf("%v", err))
                    return
                }

                mode := cipher.NewCBCEncrypter(block, iv)
                mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

                encodedArea.SetText(fmt.Sprintf("%x", ciphertext))
            }
        })
        buttonDecode.OnClicked(func(*ui.Button) {
            keyEnc := string(keyArea.Text())
            if len(keyEnc) == 0 {
                data, err := base64.StdEncoding.DecodeString(encodedArea.Text())
                if err != nil {
                    decodedArea.SetText(fmt.Sprintf("%v", err))
                } else {
                    decodedArea.SetText(string(data))
                }
            } else {               
                key := []byte(keyEnc)
                ciphertext, _ := hex.DecodeString(encodedArea.Text())

                block, err := aes.NewCipher(key)
                if err != nil {
                    decodedArea.SetText(fmt.Sprintf("%v", err))
                    return                    
                }

                if len(ciphertext) < aes.BlockSize {
                    decodedArea.SetText("ciphertext too short")
                    return
                }

                iv := ciphertext[:aes.BlockSize]
                ciphertext = ciphertext[aes.BlockSize:]

                if len(ciphertext)%aes.BlockSize != 0 {
                    decodedArea.SetText("ciphertext is not a multiple of the block size")
                    return
                }

                mode := cipher.NewCBCDecrypter(block, iv)
                mode.CryptBlocks(ciphertext, ciphertext)

                decodedArea.SetText(fmt.Sprintf("%s", ciphertext))
            }
        })
        window.OnClosing(func(*ui.Window) bool {
            ui.Quit()
            return true
        })
        window.Show()
    })
    if err != nil {
        panic(err)
    }
}
