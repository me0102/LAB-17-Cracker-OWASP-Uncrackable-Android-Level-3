# LAB-17-Cracker-OWASP-Uncrackable-Android-Level-3

> **Source du challenge** : [OWASP Mobile Security Testing Guide (MASTG)](https://github.com/OWASP/owasp-mastg)
> **Mission** : Retrouver le code secret dissimulé dans une application Android fortement protégée
> **Niveau** : ⭐⭐⭐ Confirmé

---

## 📋 Sommaire

1. [Vue d'ensemble du challenge](#-vue-densemble-du-challenge)
2. [Environnement de travail](#-environnement-de-travail)
3. [Décompilation et lecture du code](#-décompilation-et-lecture-du-code)
4. [Mécanismes de protection identifiés](#-mécanismes-de-protection-identifiés)
5. [Modifications Smali — Contournement des défenses](#-modifications-smali--contournement-des-défenses)
6. [Reconstruction et signature de l'APK](#-reconstruction-et-signature-de-lapk)
7. [Déploiement sur émulateur](#-déploiement-sur-émulateur)
8. [Reverse de libfoo.so — Récupération du secret](#-reverse-de-libfooso--récupération-du-secret)
9. [Synthèse de l'approche](#-synthèse-de-lapproche)

---

## 🎯 Vue d'ensemble du challenge

UnCrackable Level 3 constitue l'épreuve la plus exigeante de la série Android proposée par l'OWASP MASTG. L'application attend que l'utilisateur saisisse un code secret valide, lequel est protégé par plusieurs couches de sécurité côté natif.

```
Package Android  : owasp.mstg.uncrackable3
Point d'entrée   : sg.vantagepoint.uncrackable3.MainActivity
Bibliothèque JNI : libfoo.so
Clé de chiffrement : "pizzapizzapizzapizzapizz" (24 caractères)
```

---

## 🛠 Environnement de travail

| Outil | Version | Rôle |
|-------|---------|------|
| **apktool** | 3.0.2 | Désassemblage et reconstruction de l'APK |
| **jadx** | latest | Décompilation vers code Java lisible |
| **apksigner** | 36.0.0 | Signature numérique de l'APK patché |
| **adb** | SDK Platform Tools | Communication avec l'émulateur Android |
| **Ghidra / IDA** | — | Analyse de la bibliothèque native |
| **Python 3** | — | Calcul du déchiffrement XOR |
| **VS Code** | — | Édition manuelle des fichiers Smali |

---

## 🔍 Décompilation et lecture du code

### Désassemblage avec apktool

```powershell
apktool d UnCrackable-Level3.apk -o uncrackable3
```

<img width="1153" height="388" alt="Désassemblage apktool" src="https://github.com/user-attachments/assets/934beb6a-f06b-48c1-889c-0e6019b25fa1" />

**Sortie attendue :**
```
I: Using Apktool 3.0.2 on UnCrackable-Level3.apk with 4 threads
I: Baksmaling classes.dex...
I: Built apk into: uncrackable3/
```

### Analyse via jadx

L'examen du fichier `MainActivity.java` décompilé révèle plusieurs éléments critiques :

```java
private static final String xorkey = "pizzapizzapizzapizzapizz";
private CodeCheck check;
static int tampered = 0;

protected void onCreate(Bundle bundle) {
    verifyLibs();               // Contrôle d'intégrité des bibliothèques
    init(xorkey.getBytes());    // Transmission de la clé XOR à la lib native
    // ...
    if (RootDetection.checkRoot1() || RootDetection.checkRoot2() ||
        RootDetection.checkRoot3() || IntegrityCheck.isDebuggable(...) ||
        tampered != 0) {
        showDialog("Rooting or tampering detected.");
    }
}

public void verify(View view) {
    String input = editText.getText().toString();
    if (this.check.check_code(input)) {
        // Validation réussie !
    }
}
```

**Observations importantes :**
- La clé XOR `"pizzapizzapizzapizzapizz"` est injectée dans la bibliothèque native via `init()`
- La logique de vérification du secret est entièrement déléguée à `CodeCheck.check_code()` — côté natif
- La variable `tampered` est surveillée en continu pour détecter toute altération

---

## 🛡 Mécanismes de protection identifiés

| Protection | Implémentation | Conséquence |
|-----------|----------------|-------------|
| **Détection root** | `checkRoot1/2/3()` | Fermeture forcée de l'application |
| **Anti-débogage** | Thread AsyncTask en boucle | Arrêt si un debugger est détecté |
| **Vérification d'intégrité** | CRC de `libfoo.so` + `classes.dex` | Passage de `tampered` à 31337 |
| **Contrôle natif** | `baz()` valide le CRC de classes.dex | Idem — `tampered = 31337` |
| **Détection debuggable** | `IntegrityCheck.isDebuggable()` | Fermeture de l'app |

---

## 🔧 Modifications Smali — Contournement des défenses

### Localisation du fichier cible

```
uncrackable3/smali/sg/vantagepoint/uncrackable3/MainActivity.smali
```

### Modification 1 — Désactiver `showDialog()`

**Code original :**
```smali
.method private showDialog(Ljava/lang/String;)V
    .locals 3
    .line 38
    new-instance v0, Landroid/app/AlertDialog$Builder;
    ; ... logique complète du dialogue ...
    return-void
.end method
```

**Code patché :**
```smali
.method private showDialog(Ljava/lang/String;)V
    .locals 3
    return-void
.end method
```

> ✅ La méthode `showDialog()` retourne immédiatement sans rien faire — tous ses appels sont neutralisés.

---

### Modification 2 — Court-circuiter la détection root/tamper dans `onCreate()`

**Code original :**
```smali
    :cond_0
    const-string v0, "Rooting or tampering detected."
    .line 127
    invoke-direct {p0, v0}, Lsg/vantagepoint/uncrackable3/MainActivity;->showDialog(Ljava/lang/String;)V
    .line 130
    :cond_1
```

**Code patché :**
```smali
    :cond_0
    goto :cond_1
    .line 130
    :cond_1
```

> ✅ Quel que soit le résultat des détections, l'exécution saute directement à `:cond_1` sans déclencher d'alerte.

---

## 📦 Reconstruction et signature de l'APK

### Recompilation

```powershell
apktool b uncrackable3 -o UnCrackable-Level3-patched.apk
```

**Sortie attendue :**
```
I: Smaling smali folder into classes.dex...
I: Building resources with aapt2...
I: Building apk file...
I: Built apk into: UnCrackable-Level3-patched.apk
```

### Localiser l'outil apksigner

```powershell
Get-ChildItem -Path "C:\Users\lenovo\AppData\Local\Android" -Recurse -Filter "apksigner.bat" | Select-Object FullName
```

```
C:\Users\lenovo\AppData\Local\Android\Sdk\build-tools\36.0.0\apksigner.bat
```

### Application de la signature avec le keystore de débogage

```powershell
& "C:\Users\lenovo\AppData\Local\Android\Sdk\build-tools\36.0.0\apksigner.bat" `
  sign --ks "C:\Users\lenovo\.android\debug.keystore" `
  --ks-pass pass:android `
  UnCrackable-Level3-patched.apk
```

---

## 📲 Déploiement sur émulateur

### Suppression de l'ancienne installation

```powershell
adb uninstall owasp.mstg.uncrackable3
# Success
```

### Installation de l'APK modifié

```powershell
adb install UnCrackable-Level3-patched.apk
# Performing Streamed Install
# Success
```

### Démarrage de l'application

```powershell
adb shell monkey -p owasp.mstg.uncrackable3 -c android.intent.category.LAUNCHER 1
# Events injected: 1
```

<img width="717" height="301" alt="Application lancée sans alerte" src="https://github.com/user-attachments/assets/ab627b80-d52c-4b88-8494-864bac848c5f" />

> ✅ L'application démarre normalement, sans déclencher le message d'erreur "Rooting or tampering detected."

---

## 🔬 Reverse de libfoo.so — Récupération du secret

### Cartographie des fonctions natives

| Fonction | Description |
|----------|-------------|
| `Java_..._MainActivity_init` | Reçoit la clé XOR et initialise le buffer chiffré |
| `Java_..._MainActivity_baz` | Retourne la valeur CRC attendue pour classes.dex |
| `Java_..._CodeCheck_check_1code` | Compare la saisie utilisateur avec le secret déchiffré |

### Démarche d'extraction

La fonction `init()` transmet `"pizzapizzapizzapizzapizz"` à la bibliothèque, qui applique une opération XOR entre cette clé et le secret encodé en dur dans le binaire.

**Procédure avec Ghidra :**
1. Importer `uncrackable3/lib/x86/libfoo.so` dans un nouveau projet
2. Lancer l'analyse automatique complète
3. Dans le Symbol Tree, rechercher la fonction `check_code`
4. Relever les octets du buffer chiffré via le décompilateur

**Script Python — Déchiffrement XOR :**

```python
key = b"pizzapizzapizzapizzapizz"

# Remplacer par les octets extraits depuis Ghidra
encrypted = bytes([...])

flag = bytes([encrypted[i] ^ key[i % len(key)] for i in range(len(encrypted))])
print("[+] Secret :", flag.decode())
```

### Approche alternative — Instrumentation Frida

```javascript
// hook.js
Java.perform(function() {
    var CodeCheck = Java.use("sg.vantagepoint.uncrackable3.CodeCheck");
    CodeCheck.check_code.implementation = function(input) {
        console.log("[*] Tentative avec la saisie : " + input);
        var result = this.check_code(input);
        console.log("[*] Réponse de la vérification : " + result);
        return result;
    };
});
```

```powershell
frida -U -f owasp.mstg.uncrackable3 -l hook.js --no-pause
```

---

## 📊 Synthèse de l'approche

```
┌─────────────────────────────────────────────────────────┐
│                 ENCHAÎNEMENT DES ÉTAPES                 │
├─────────────────────────────────────────────────────────┤
│  1. apktool d  →  Désassembler l'APK en Smali           │
│  2. jadx       →  Lire la logique Java décompilée       │
│  3. Smali      →  Patcher showDialog() + vérif. root    │
│  4. apktool b  →  Reconstruire l'APK                    │
│  5. apksigner  →  Signer avec le keystore de debug      │
│  6. adb        →  Pousser sur l'émulateur               │
│  7. Ghidra     →  Disséquer libfoo.so                   │
│  8. XOR Python →  Déchiffrer et lire le secret          │
└─────────────────────────────────────────────────────────┘
```

### Récapitulatif des protections contournées

- [x] Détection root (checkRoot1 / checkRoot2 / checkRoot3)
- [x] Contrôle d'intégrité (CRC bibliothèques + classes.dex)
- [x] Dialogue d'alerte neutralisé
- [ ] Anti-débogage (thread AsyncTask) — contournable via Frida
- [ ] Logique de vérification native (check_code) — à analyser dans Ghidra

---

## 📚 Ressources

- [Dépôt officiel OWASP MASTG](https://github.com/OWASP/owasp-mastg)
- [Documentation apktool](https://apktool.org/)
- [Documentation Frida](https://frida.re/docs/)
- [Ghidra (NSA)](https://ghidra-sre.org/)

---

*Writeup réalisé dans une démarche pédagogique — dans le cadre de l'OWASP Mobile Security Testing Guide*
