Ajouter JAVA_HOME :
Dans la section "Variables système", cliquez sur "Nouveau".
Nom de la variable : JAVA_HOME
Valeur de la variable : le chemin d'installation du JDK, par exemple C:\Program Files\Java\jdk-11.
Mettre à jour la variable Path :

Dans la section "Variables système", trouvez la variable Path et cliquez sur "Modifier".
Cliquez sur "Nouveau" et ajoutez %JAVA_HOME%\bin.
Cliquez sur "OK" pour fermer toutes les fenêtres de configuration.


keytool -genkeypair -alias myalias -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore keystore.p12 -validity 3650



curl -v -k https://localhost:8443/hello


curl -v http://localhost:8080/hello
