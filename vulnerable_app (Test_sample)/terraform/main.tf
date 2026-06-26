terraform {
  required_version = ">= 0.12"
}

# SECURITY ISSUE: Publicly open security group
resource "aws_security_group" "allow_all" {
  name        = "allow_all"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 0
    to_port     = 65535
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

# SECURITY ISSUE: Hardcoded secrets in Terraform
resource "aws_db_instance" "default" {
  allocated_storage    = 20
  engine               = "mysql"
  instance_class       = "db.t2.micro"
  username             = "admin"
  password             = "password123"
  publicly_accessible  = true
  skip_final_snapshot  = true
}
