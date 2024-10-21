provider "aws" {
  region  = "us-east-1"
  profile = "terraform-test"
}

# Variáveis
variable "projeto" {
  description = "Nome do projeto"
  type        = string
  default     = "VExpenses"

  validation {
    condition     = length(var.projeto) > 3
    error_message = "O nome do projeto deve ter mais de 3 caracteres."
  }
}

variable "candidato" {
  description = "Nome do candidato"
  type        = string
  default     = "SeuNome"

  validation {
    condition     = length(var.candidato) > 3
    error_message = "O nome do candidato deve ter mais de 3 caracteres."
  }
}

variable "allowed_ips" {
  description = "IPs permitidos para acesso SSH"
  type        = list(string)
  default     = ["YOUR_ALLOWED_IP/32"]  # Substitua pelo seu IP específico
}

# Módulo VPC
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  version = "3.14.0"  # Verifique a versão mais recente

  name = "${var.projeto}-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["us-east-1a", "us-east-1b"]  # Múltiplas AZs
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets  = ["10.0.3.0/24", "10.0.4.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = true

  tags = {
    Name = "${var.projeto}-vpc"
  }
}

# KMS Key para criptografia
resource "aws_kms_key" "ebs_key" {
  description             = "KMS key for EBS encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

# Security Group Aprimorado
resource "aws_security_group" "main_sg" {
  name        = "${var.projeto}-${var.candidato}-sg"
  description = "Security group for EC2 instance"
  vpc_id      = module.vpc.vpc_id

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

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.projeto}-${var.candidato}-sg"
    Project = var.projeto
  }
}

# Instância EC2 com configuração do Nginx e monitoramento
resource "aws_instance" "debian_ec2" {
  ami           = data.aws_ami.debian12.id
  instance_type = "t2.micro"
  subnet_id     = module.vpc.public_subnets[0]
  key_name      = aws_key_pair.ec2_key_pair.key_name

  vpc_security_group_ids = [aws_security_group.main_sg.id]

  associate_public_ip_address = true

  root_block_device {
    volume_size           = 20
    volume_type          = "gp2"
    encrypted            = true
    kms_key_id           = aws_kms_key.ebs_key.arn
    delete_on_termination = true
  }

  user_data = <<-EOF
              #!/bin/bash
              apt-get update -y
              apt-get upgrade -y
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

  tags = {
    Name        = "${var.projeto}-${var.candidato}-ec2"
    Project     = var.projeto
    Environment = "test"
    Managed_by  = "terraform"
  }
}

# Automação de Snapshots
resource "aws_ebs_snapshot" "ebs_snapshot" {
  volume_id = aws_instance.debian_ec2.root_block_device[0].volume_id
  tags = {
    Name = "${var.projeto}-snapshot-${timestamp()}"
  }
}

# Outputs
output "private_key" {
  description = "Chave privada para acesso SSH"
  value       = tls_private_key.ec2_key.private_key_pem
  sensitive   = true
}

output "public_ip" {
  description = "IP público da instância EC2"
  value       = aws_instance.debian_ec2.public_ip
}

output "nginx_url" {
  description = "URL para acesso ao Nginx"
  value       = "http://${aws_instance.debian_ec2.public_ip}"
}