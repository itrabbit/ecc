Compatible with swift library https://github.com/IBM-Swift/BlueECC

### Example usage

```go
package main

import (
	"fmt"
	"github.com/itrabbit/ecc"
)

func main()  {
        private, err := ecc.GenerateKey()
        if err != nil {
            panic(err.Error())
        }

        encrypted, err := ecc.Encrypt(&private.PublicKey, []byte("hello"))
        if err != nil {
            panic(err.Error())
        }

        fmt.Println("encrypted", encrypted, len(encrypted));
        // -> encrypted [4 13 13 236 218 227 ... 89] 86

        decrypted, err := ecc.Decrypt(private, encrypted)
        if err != nil {
            panic(err.Error())
        }

        fmt.Println("decrypted", decrypted, string(decrypted))
        // -> decrypted [104 101 108 108 111] hello
}
```