# Desafio DevOps - VExpenses

## Tarefa 1: Análise Técnica do Código Terraform

### Análise Detalhada da Infraestrutura Original

#### 1. Provider e Configurações Básicas
- Utiliza provider AWS na região us-east-1
- Define variáveis para nome do projeto e candidato
- Não implementa uso de profile AWS
- Ausência de validações nas variáveis

#### 2. Recursos de Rede
- **VPC (Virtual Private Cloud)**:
  - CIDR: 10.0.0.0/16
  - DNS Hostnames habilitado
  - DNS Support habilitado
  - Sem implementação de módulos AWS

- **Subnet**:
  - CIDR: 10.0.1.0/24
  - Zona de disponibilidade: us-east-1a
  - Subnet pública única
  - Sem implementação de múltiplas AZs

- **Internet Gateway**:
  - Anexado à VPC principal
  - Permite acesso à internet pública

- **Route Table**:
  - Rota padrão (0.0.0.0/0) direcionada ao Internet Gateway
  - Associação com a subnet pública

#### 3. Recursos de Segurança
- **Security Group**:
  - Permite SSH (porta 22) de qualquer IP (0.0.0.0/0)
  - Permite todo tráfego de saída
  - Sem restrições de IP específicos
  - Sem regras para porta 80 (HTTP)

- **Key Pair**:
  - Geração de chave RSA 2048 bits
  - Chave privada exposta nos outputs
  - Sem rotação de chaves implementada

#### 4. Recursos de Computação
- **Instância EC2**:
  - Tipo: t2.micro
  - AMI: Debian 12
  - Volume EBS 20GB GP2
  - Sem criptografia de volume
  - User data básico apenas com updates
  - Sem tags adequadas
  - Sem monitoramento configurado

#### 5. Outputs
- Exibe chave privada sem flag sensitive
- Exibe IP público da instância
- Ausência de outputs úteis adicionais

### Observações Técnicas Adicionais
1. **Segurança**:
   - Ausência de criptografia nos volumes
   - Security Group muito permissivo
   - Falta de políticas de backup
   - Ausência de monitoramento

2. **Rede**:
   - Arquitetura simples sem redundância
   - Única zona de disponibilidade
   - Ausência de NAT Gateway

3. **Boas Práticas**:
   - Falta de tags padronizadas
   - Ausência de módulos Terraform
   - Falta de validações
   - Ausência de versionamento de estado

## Tarefa 2: Modificações e Melhorias Implementadas

### 1. Melhorias de Segurança

#### 1.1 Configuração AWS
```hcl
provider "aws" {
  region  = "us-east-1"
  profile = "terraform-test"
}
```
- Implementação de profile específico
- Melhoria na gestão de credenciais
- Separação de ambientes

#### 1.2 Criptografia e Proteção de Dados
```hcl
resource "aws_kms_key" "ebs_key" {
  description             = "KMS key for EBS encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}
```
- Chave KMS dedicada
- Rotação automática habilitada
- Período de retenção definido

#### 1.3 Security Group Aprimorado
```hcl
resource "aws_security_group" "main_sg" {
  ingress {
    description = "SSH from allowed IPs"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_ips
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```
- Restrição de IPs para SSH
- Regra específica para HTTP
- Descrições detalhadas das regras

### 2. Automação e Configuração

#### 2.1 Instalação e Configuração do Nginx
```hcl
user_data = <<-EOF
#!/bin/bash
# Atualização do sistema
apt-get update -y
apt-get upgrade -y

# Instalação do Nginx
apt-get install -y nginx
systemctl enable nginx
systemctl start nginx

# Configuração de logs
mkdir -p /var/log/nginx
chmod 755 /var/log/nginx

# Configuração do Nginx
cat <<'NGINX' > /etc/nginx/conf.d/default.conf
server {
    listen 80;
    server_name _;
    
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    location / {
        root /var/www/html;
        index index.html;
    }
}
NGINX

# Script de monitoramento
cat <<'HEALTH' > /usr/local/bin/health_check.sh
#!/bin/bash
if systemctl is-active --quiet nginx; then
    echo "Nginx is running"
    exit 0
else
    echo "Nginx is not running"
    systemctl start nginx
    if systemctl is-active --quiet nginx; then
        echo "Nginx restarted successfully"
        exit 0
    else
        echo "Failed to restart Nginx"
        exit 1
    fi
fi
HEALTH
chmod +x /usr/local/bin/health_check.sh

# Configuração do cron para health check
echo "*/5 * * * * /usr/local/bin/health_check.sh >> /var/log/nginx/health_check.log 2>&1" | crontab -
EOF
```

### 3. Outras Melhorias Implementadas

#### 3.1 Módulos e Organização
- Utilização do módulo VPC da AWS
- Separação lógica dos recursos
- Padronização de nomenclatura

#### 3.2 Validações e Tags
- Validação de variáveis
- Sistema de tags consistente
- Nomenclatura padronizada

#### 3.3 Monitoramento e Logs
- Script de health check
- Configuração de logs do Nginx
- Monitoramento automático via cron

#### 3.4 Backup e Recuperação
- Snapshot automation
- Retenção de backups
- Estratégia de recuperação

## Instruções Detalhadas de Uso

### 1. Pré-requisitos
- AWS CLI versão 2.x ou superior
- Terraform versão >= 1.0.0
- Conta AWS com permissões adequadas
  - EC2
  - VPC
  - IAM
  - KMS

### 2. Configuração do Ambiente

#### 2.1 Configuração do AWS CLI
```bash
aws configure --profile terraform-test
AWS Access Key ID [None]: YOUR_ACCESS_KEY
AWS Secret Access Key [None]: YOUR_SECRET_KEY
Default region name [None]: us-east-1
Default output format [None]: json
```

#### 2.2 Variáveis de Ambiente
```bash
export AWS_PROFILE=terraform-test
export AWS_REGION=us-east-1
```

### 3. Execução do Terraform

#### 3.1 Inicialização
```bash
terraform init
```

#### 3.2 Validação
```bash
terraform validate
```

#### 3.3 Planejamento
```bash
terraform plan -out=tfplan
```

#### 3.4 Aplicação
```bash
terraform apply tfplan
```

### 4. Validação da Infraestrutura

#### 4.1 Verificação do Nginx
```bash
curl -I http://<ec2_public_ip>
```

#### 4.2 Verificação dos Logs
```bash
ssh -i private_key.pem admin@<ec2_public_ip> 'sudo tail -f /var/log/nginx/access.log'
```

#### 4.3 Teste do Health Check
```bash
ssh -i private_key.pem admin@<ec2_public_ip> 'sudo /usr/local/bin/health_check.sh'
```

### 5. Limpeza da Infraestrutura
```bash
terraform destroy
```
