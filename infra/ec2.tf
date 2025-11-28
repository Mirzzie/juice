provider "aws" {
  region = "eu-west-1"
}

# Look up the default VPC
data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "juice_sg" {
  name        = "juice-sec-thesis-sg"
  description = "Security Group for DevSecOps Thesis Experiment"
  vpc_id      = data.aws_vpc.default.id

  # --- MANAGEMENT ---
  ingress {
    description = "SSH Access (Ansible/GitHub Actions)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # --- APPLICATION ---
  ingress {
    description = "Juice Shop App (HTTP)"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # --- OBSERVABILITY DASHBOARDS ---
  ingress {
    description = "Grafana Dashboard"
    from_port   = 3001
    to_port     = 3001
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Prometheus UI"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # --- TELEMETRY & AGENTS ---
  ingress {
    description = "Thesis Metrics Exporter (Python)"
    from_port   = 9999
    to_port     = 9999
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "DataDog APM / Trace Agent"
    from_port   = 8126
    to_port     = 8126
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # --- OPENTELEMETRY (OTEL) ---
  ingress {
    description = "OTel Collector gRPC Receiver"
    from_port   = 4317
    to_port     = 4317
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "OTel Collector HTTP Receiver"
    from_port   = 4318
    to_port     = 4318
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "OTel Prometheus Exporter"
    from_port   = 8889
    to_port     = 8889
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # --- OUTBOUND ---
  egress {
    description = "Allow all outbound traffic (Updates/API Calls)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "juice-sec-group"
    Project = "MSc-DevSecOps-Thesis"
  }
}

resource "aws_instance" "juice" {
  ami                    = var.ami_id
  instance_type          = "t3.medium"
  key_name               = "sec"
  vpc_security_group_ids = [aws_security_group.juice_sg.id]

  # Increase volume size for Docker images and Logs
  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name    = "juice-shop-thesis-instance"
    Project = "MSc-DevSecOps-Thesis"
  }
}

# --- STATIC IP CONFIGURATION ---
resource "aws_eip" "juice_static_ip" {
  instance = aws_instance.juice.id
  domain   = "vpc"

  tags = {
    Name    = "juice-static-ip"
    Project = "MSc-DevSecOps-Thesis"
  }
}

output "juice_public_ip" {
  description = "Static Public IP"
  value       = aws_eip.juice_static_ip.public_ip
}
