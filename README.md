# AV Scan

Scanner de segurança para Android que analisa os apps instalados e aponta sinais típicos de trojans e spyware. Sem anúncios, sem internet, sem coleta de dados.

## O que faz
- Compara o SHA-256 de cada APK com uma lista de malwares conhecidos (`app/src/main/assets/signatures.txt`).
- Pontua o risco de cada app por permissões sensíveis (SMS, sobreposição de tela, instalar pacotes), serviços de acessibilidade, administrador do dispositivo e leitura de notificações.
- Considera a origem da instalação (Play Store, Samsung, Amazon, Epic) e apps ocultos.
- Mostra um veredito em palavras e o motivo de cada alerta.

## Limitações (leia antes de confiar)
- É **heurístico**: não analisa o código dos apps. Pode errar para os dois lados.
- Só afirma "malware conhecido" quando o hash está na lista, que começa vazia.
- **Não substitui** o Google Play Protect nem um antivírus comercial.
- A lista `knownGood` em `Scanner.kt` é pequena e só vale para apps vindos de loja confiável.

## Como compilar
**Android Studio:** abra a pasta e use Build > Build APK.

**GitHub Actions:** cada push gera o APK em Actions > Artifacts.

**Termux:**
```
pkg install openjdk-21 aapt2 wget unzip
# instale o Gradle 8.7 e o SDK (platforms;android-34, build-tools;34.0.0)
echo "sdk.dir=$HOME/android-sdk" > local.properties
echo "android.aapt2FromMavenOverride=$PREFIX/bin/aapt2" >> gradle.properties
~/gradle-8.7/bin/gradle assembleDebug --no-daemon
```

## Ideias para contribuir
- Atualizar `signatures.txt` automaticamente (MalwareBazaar).
- Ampliar a lista de apps conhecidos e de lojas confiáveis.
- Verificar o certificado de assinatura dos apps.
- Varredura de APKs soltos em Downloads.
- Interface em Compose e tradução.

Licença: MIT
