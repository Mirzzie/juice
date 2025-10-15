provider "aws" {
  region = "eu-west-1"
}

# Look up the default VPC
data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "juice_sg" {
  name        = "juice-sg"
  description = "Allow SSH and app port"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

    ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

      ingress {
    from_port   = 4000
    to_port     = 4000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "juice" {
  ami                    = var.ami_id
  instance_type          = "t3.micro"
  key_name               = "sec"
  vpc_security_group_ids = [aws_security_group.juice_sg.id]

  tags = {
    Name = "juice"
  }
}

output "juice_public_ip" {
  value = aws_instance.juice.public_ip
}
