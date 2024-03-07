<p align="center">
<img align="center" width="500" height="330" src="https://raw.githubusercontent.com/AM71113363/SSL-SelfSignedCA/master/info.png">
</p>

# SSL-SelfSignedCA
-----

## INFO:<br>
1. If you don't have a PrivateKey you can use [PrivateKeyGenerator](https://github.com/AM71113363/SSL-PrivateKeyGenerator).<br>
2. The PrivateKey must have the ".key" extention.<br>
3. Drag-Drop the .key file (PEM or DER format) to create a SelfSigned CA certificate.<br>
4. The MSG "OK" will appear and the new certificate will have the same name as the key,but with ".crt" extention.<br>
5. Errors: if the MSG has the ErrorCode it means the error was generated from mbedtls lib,otherwise was from the App itself.<br>

## Build.
Source code of SSLlib.a<br>
.Can be found in [Mbedtls-Builds](https://github.com/AM71113363/Mbedtls-Builds)<br>
.Or from the original source [Mbed-TLS](https://github.com/Mbed-TLS/mbedtls)<br>

# NOTE
.Drag-Drop a certificate and the info's will be displayed<br>
.Any file without the ".key" extention will be considered as a certificate file and the App will try to read it anyway.<br>

