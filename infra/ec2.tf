provider "aws" {
  region = "eu-west-1"
}

# Look up the default VPC
data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "juice_sg" {
  name        = "juice-sg"
  description = "Allow SSH, Juice Shop app, and Datadog APM"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH Access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Juice Shop Application"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Juice Shop Application"
    from_port   = 3001
    to_port     = 3001
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Juice Shop Application"
    from_port   = 9090
    to_port     = 9090
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

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "juice" {
  ami                    = var.ami_id
  instance_type          = "t3.medium"
  key_name               = "sec"
  vpc_security_group_ids = [aws_security_group.juice_sg.id]

  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name = "juice"
  }
}

output "juice_public_ip" {
  value = aws_instance.juice.public_ip
}
