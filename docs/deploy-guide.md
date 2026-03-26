# Guia de Deploy — Ubuntu Desk

## Requisitos do servidor

- Ubuntu 22.04 LTS ou superior
- 1 vCPU, 1 GB RAM mínimo (Hostinger KVM 1 é suficiente)
- Docker + Docker Compose v2
- Portas abertas: 21115-21119/tcp, 21116/udp, 8088/tcp (admin), 80/tcp, 443/tcp (nginx futuro)

## 1. Preparação inicial

```bash
ssh root@SEU_IP
apt update && apt upgrade -y
```

## 2. Clonar o repositório

```bash
git clone https://github.com/felipediasz1/Ubuntu-Desk- /opt/ubuntu-desk
cd /opt/ubuntu-desk
```

## 3. Configurar variáveis de ambiente

```bash
cp server/.env.example server/.env
nano server/.env
# Preencher: RELAY_HOST, ADMIN_PASSWORD
```

## 4. Rodar o script de setup automático

```bash
sudo bash server/setup-server.sh
```

Este script:
- Instala Docker e Docker Compose v2
- Configura UFW (portas 21115-21119 e 8088)
- Sobe os serviços (hbbs, hbbr, admin) via docker compose
- Captura a RS_PUB_KEY automaticamente e atualiza o `.env`

## 5. Capturar RS_PUB_KEY (se o script não capturou)

```bash
docker exec ubuntu-desk-hbbs cat /root/id_ed25519.pub
# Copiar o valor e colar em server/.env → RS_PUB_KEY=...
docker compose -f server/docker-compose.yml restart
```

## 6. Verificar os serviços

```bash
docker compose -f server/docker-compose.yml ps
# Todos devem estar "running"

curl http://SEU_IP:8088
```

## 7. Atualizar o cliente com o novo IP

Se o IP mudou (ex: de 192.168.18.4 para o IP do servidor de produção):

1. Editar `client/libs/hbb_common/src/config.rs`:
   ```
   pub const RENDEZVOUS_SERVERS: &str = "SEU_NOVO_IP";
   ```
2. Rebuild: `.\build\build_windows.ps1 -Release`
3. Distribuir o novo instalador para os usuários
4. Testar: abrir o cliente → confirmar que um ID é gerado → tentar conexão

## 8. SSL/TLS com nginx (recomendado para produção)

```bash
apt install nginx certbot python3-certbot-nginx -y

cat > /etc/nginx/sites-available/ubuntu-desk <<'EOF'
server {
    server_name admin.SEU_DOMINIO.com;
    location / {
        proxy_pass http://127.0.0.1:8088;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
EOF

ln -s /etc/nginx/sites-available/ubuntu-desk /etc/nginx/sites-enabled/
certbot --nginx -d admin.SEU_DOMINIO.com
```

Após ativar HTTPS: setar `HTTPS_ONLY=1` no `server/.env` e reiniciar:

```bash
docker compose -f server/docker-compose.yml restart admin
```

## 9. Ativar 2FA no painel admin (recomendado)

1. Acessar o painel → **Configurações** → **Configurar 2FA**
2. Escanear o QR code com Google Authenticator ou Authy
3. Salvar os códigos de recuperação em local seguro

Em caso de perda do autenticador:
```bash
python admin/cli.py disable-2fa admin
docker compose -f server/docker-compose.yml restart admin
```

## Checklist de validação pós-deploy

- [ ] `docker compose ps` — todos os containers running
- [ ] Painel admin acessível em `http://SEU_IP:8088`
- [ ] Login com senha alterada (não `ubuntu-desk-admin`)
- [ ] 2FA configurado
- [ ] Cliente Windows conecta e gera ID
- [ ] Conexão remota funcionando (teste entre dois dispositivos)
- [ ] RS_PUB_KEY preenchida no `.env` e no `config.rs` do cliente
