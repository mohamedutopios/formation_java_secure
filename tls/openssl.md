La sortie obtenue montre que la requête a réussi et que la réponse du serveur a été reçue. Cependant, certains détails du handshake TLS ne sont pas affichés parce que `curl` sur Windows utilise le backend `schannel` pour les connexions SSL/TLS, ce qui peut ne pas afficher les mêmes détails que sur d'autres systèmes.

Pour obtenir une sortie plus détaillée du handshake TLS sur Windows, vous pouvez utiliser `openssl s_client`, un outil inclus avec OpenSSL, pour établir une connexion TLS et afficher les détails du handshake. Voici comment faire :

### Étape 1 : Installer OpenSSL sur Windows

1. Téléchargez et installez OpenSSL pour Windows depuis [Shining Light Productions](https://slproweb.com/products/Win32OpenSSL.html). Assurez-vous de télécharger la version `Win64 OpenSSL` pour correspondre à votre architecture système.

2. Pendant l'installation, choisissez d'ajouter OpenSSL à la variable PATH du système.

### Étape 2 : Utiliser `openssl s_client` pour afficher les détails du handshake TLS

1. **Ouvrez une invite de commandes** en tant qu'administrateur.

2. **Exécutez la commande `openssl s_client`** pour se connecter au serveur TLS :

```sh
openssl s_client -connect localhost:8443
```

Cela affichera des détails complets sur la connexion TLS, y compris les informations sur le certificat, les algorithmes de chiffrement utilisés, et le processus de handshake.

### Exemple de sortie attendue

Lorsque vous exécutez cette commande, vous devriez voir une sortie détaillée semblable à celle-ci :

```
CONNECTED(00000003)
depth=0 CN = localhost
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = localhost
verify return:1
---
Certificate chain
 0 s:CN = localhost
   i:CN = localhost
---
Server certificate
-----BEGIN CERTIFICATE-----
MIID...
-----END CERTIFICATE-----
subject=CN = localhost
issuer=CN = localhost
---
No client certificate CA names sent
Peer signing digest: SHA256
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1456 bytes and written 305 bytes
Verification error: self signed certificate
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server public key is 2048 bit
Secure Renegotiation IS supported
...
---
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 16A8...
    Session-ID-ctx: 
    Master-Key: 7A3B...
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    Start Time: 1612123456
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: yes
---
```

### Conclusion

En utilisant `openssl s_client`, vous pouvez obtenir une vue détaillée du handshake TLS et de la connexion sécurisée, ce qui met en évidence les avantages de TLS en matière de sécurité des communications. Si vous rencontrez toujours des problèmes ou avez besoin d'une sortie spécifique de `curl`, vous pouvez essayer d'utiliser `curl` sur un système Linux ou Mac où OpenSSL est utilisé comme backend SSL/TLS.